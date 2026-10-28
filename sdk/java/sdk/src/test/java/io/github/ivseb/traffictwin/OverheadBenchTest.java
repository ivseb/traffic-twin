package io.github.ivseb.traffictwin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.ivseb.traffictwin.sanitizer.Exchange;
import io.github.ivseb.traffictwin.sanitizer.Exchange.Header;
import io.github.ivseb.traffictwin.sanitizer.Json;
import io.github.ivseb.traffictwin.sanitizer.KeyRing;
import io.github.ivseb.traffictwin.sanitizer.Policy;
import io.github.ivseb.traffictwin.sanitizer.PolicyValidator;
import io.github.ivseb.traffictwin.sanitizer.Sanitizer;
import io.github.ivseb.traffictwin.support.Harness;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

/**
 * Simple overhead benchmark (no JMH): the sanitizer on a typical exchange, and the same Jetty app
 * with the agent off and on. Each POST /orders is one inbound exchange plus two outbound calls,
 * so with the agent on three exchanges are captured, sanitized and exported over mTLS to a fake
 * tt-core in this JVM. Duration per phase: {@code -Dtt.bench.seconds} (default 3).
 */
class OverheadBenchTest {
    static final String BODY = "{\"items\":[{\"sku\":\"TSHIRT-RED-M\",\"qty\":2},{\"sku\":\"MUG-BLUE\",\"qty\":1}],\"email\":\"giulia.neri@example.com\",\"note\":\"leave at the door\"}";

    static double[] stats(List<Double> lat) {
        double[] a = lat.stream().mapToDouble(Double::doubleValue).sorted().toArray();
        return new double[] {a[a.length / 2], a[Math.min(a.length - 1, (int) (a.length * 0.99))], a.length};
    }

    @Test
    void sanitizerCostPerExchange() throws Exception {
        Object body = Json.parsePlain(Files.readAllBytes(ConformanceTest.dir().resolve("policies/empty.json")), true);
        Policy p = new Policy(PolicyValidator.validate(body));
        Sanitizer s = new Sanitizer(p, KeyRing.parse(Harness.HMAC_KEY).select(p));
        Exchange ex = new Exchange();
        ex.inbound = true;
        ex.serviceName = "shop-api";
        ex.method = "POST";
        ex.rawPath = "/orders/ORD-2026-000184".getBytes(StandardCharsets.UTF_8);
        ex.rawQuery = "promo=AUTUMN10".getBytes(StandardCharsets.UTF_8);
        ex.reqHeaders = new ArrayList<>(List.of(new Header("Content-Type", "application/json".getBytes()), new Header("User-Agent", "bench/1.0".getBytes()),
            new Header("Cookie", "sid=9f8e7d6c5b4a".getBytes()), new Header("Accept", "*/*".getBytes())));
        ex.reqBody = BODY.getBytes(StandardCharsets.UTF_8);
        ex.status = 201;
        ex.respHeaders = new ArrayList<>(List.of(new Header("Content-Type", "application/json".getBytes())));
        ex.respBody = "{\"id\":\"ORD-2026-000184\",\"status\":\"CREATED\",\"total\":73.40}".getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < 30_000; i++) s.run(ex, System.currentTimeMillis(), null);
        int n = 100_000;
        long t0 = System.nanoTime();
        for (int i = 0; i < n; i++) assertEquals("event", s.run(ex, System.currentTimeMillis(), null).outcome);
        double us = (System.nanoTime() - t0) / 1000.0 / n;
        System.out.printf("[bench] sanitizer: %.1f us per exchange (typical order, empty policy)%n", us);
        assertTrue(us < 500, "sanitizer unexpectedly slow: " + us + " us");
    }

    private double[] sequential(Harness h, double seconds) throws Exception {
        List<Double> lat = new ArrayList<>();
        long end = System.nanoTime() + (long) (seconds * 1e9);
        HttpRequest rq = HttpRequest.newBuilder(URI.create(h.appUrl("/orders"))).header("content-type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(BODY)).build();
        while (System.nanoTime() < end) {
            long t = System.nanoTime();
            HttpResponse<Void> r = h.plain.send(rq, HttpResponse.BodyHandlers.discarding());
            lat.add((System.nanoTime() - t) / 1e6);
            assertEquals(201, r.statusCode());
        }
        return stats(lat);
    }

    private double throughput(Harness h, double seconds, int conc) throws Exception {
        ExecutorService ex = Executors.newFixedThreadPool(conc);
        List<Double> done = new CopyOnWriteArrayList<>();
        long end = System.nanoTime() + (long) (seconds * 1e9);
        HttpRequest rq = HttpRequest.newBuilder(URI.create(h.appUrl("/orders"))).header("content-type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(BODY)).build();
        List<java.util.concurrent.Future<?>> fs = new ArrayList<>();
        for (int i = 0; i < conc; i++) {
            fs.add(ex.submit(() -> {
                int n = 0;
                while (System.nanoTime() < end) {
                    h.plain.send(rq, HttpResponse.BodyHandlers.discarding());
                    n++;
                }
                done.add((double) n);
                return null;
            }));
        }
        for (var f : fs) f.get();
        ex.shutdown();
        return done.stream().mapToDouble(Double::doubleValue).sum() / seconds;
    }

    @Test
    void endToEndOverheadOfTheAgent() throws Exception {
        double secs = Double.parseDouble(System.getProperty("tt.bench.seconds", "3"));
        try (Harness h = new Harness()) {
            h.startAppOnly();
            sequential(h, 1.5); // warm-up
            double[] offSeq = sequential(h, secs);
            double offRps = throughput(h, secs, 8);
            h.startAgent(h.policy(), false);
            sequential(h, 1.5);
            double[] onSeq = sequential(h, secs);
            double onRps = throughput(h, secs, 8);
            h.tt.flush();
            Map<String, Object> st = h.tt.status();
            System.out.printf("[bench] sequential  agent off: p50 %.2f ms  p99 %.2f ms (%d req)%n", offSeq[0], offSeq[1], (long) offSeq[2]);
            System.out.printf("[bench] sequential  agent on : p50 %.2f ms  p99 %.2f ms (%d req)%n", onSeq[0], onSeq[1], (long) onSeq[2]);
            System.out.printf("[bench] added latency per order (3 exchanges captured): p50 %+.2f ms, p99 %+.2f ms%n", onSeq[0] - offSeq[0], onSeq[1] - offSeq[1]);
            System.out.printf("[bench] throughput 8 clients: off %.0f req/s, on %.0f req/s (%.1f%%)%n", offRps, onRps, 100.0 * (onRps - offRps) / offRps);
            System.out.printf("[bench] agent: %s%n", st);
            assertTrue(onSeq[0] - offSeq[0] < 5.0, "added p50 latency must stay small");
            assertEquals(0L, st.get("sanitizer_errors"));
        }
    }
}
