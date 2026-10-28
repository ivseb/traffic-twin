package io.github.ivseb.traffictwin;

import static io.github.ivseb.traffictwin.support.FakeCore.list;
import static io.github.ivseb.traffictwin.support.FakeCore.map;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.ivseb.traffictwin.sanitizer.Json;
import io.github.ivseb.traffictwin.support.FakeCore;
import io.github.ivseb.traffictwin.support.Harness;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * End to end: a Jetty app with the servlet filter and the HttpClient wrapper, a fake carrier and a
 * fake tt-core (enrollment with CA pin, mTLS heartbeat, signed policy, OTLP intake). Asserts the
 * sanitized events and that the app's traffic is unchanged.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CaptureIntegrationTest {
    Harness h;

    @BeforeAll
    void setUp() throws Exception {
        h = new Harness();
        h.extraServlets.put("/parse", new StreamingParserServlet());
        h.start(h.policy(), true);
    }

    @AfterAll
    void tearDown() throws Exception {
        if (h != null) h.close();
    }

    /** Reads a JSON document like Jackson does under Spring's @RequestBody: stops at the closing brace (or after {@code stopAfter} bytes), never reads the end of the stream. */
    static final class StreamingParserServlet extends jakarta.servlet.http.HttpServlet {
        @Override
        protected void doPost(jakarta.servlet.http.HttpServletRequest req, jakarta.servlet.http.HttpServletResponse res) throws java.io.IOException {
            String stop = req.getParameter("stopAfter");
            int max = stop == null ? Integer.MAX_VALUE : Integer.parseInt(stop);
            java.io.InputStream in = req.getInputStream();
            byte[] buf = new byte[stop == null ? 8000 : max];
            int depth = 0;
            boolean started = false;
            long total = 0;
            while ((!started || depth > 0) && total < max) {
                int n = in.read(buf);
                if (n < 0) break;
                total += n;
                for (int i = 0; i < n; i++) {
                    if (buf[i] == '{') {
                        depth++;
                        started = true;
                    } else if (buf[i] == '}') {
                        depth--;
                    }
                }
            }
            res.setStatus(200);
            res.setContentType("application/json");
            res.getWriter().write("{\"read\":" + total + "}");
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) {
        return (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    static List<Object> l(Object o) {
        return (List<Object>) o;
    }

    @Test
    @Order(0)
    void enrollmentUsesNoCsrAndStoresTheKeyInAPrivatePkcs12() throws Exception {
        assertEquals(1, h.core.enrollments.size());
        Map<String, Object> e = h.core.enrollments.get(0);
        assertFalse(e.containsKey("csr"), "the no-CSR path");
        Map<String, Object> src = m(e.get("source"));
        assertEquals("sdk-java", src.get("kind"));
        assertEquals("shop-api", src.get("service_name"));
        assertEquals(list("k1"), src.get("hmac_kids"));
        Path dir = h.stateDir.resolve("s");
        assertEquals("rwx------", perms(dir));
        try (Stream<Path> files = Files.list(dir)) {
            for (Path f : files.toList()) {
                assertEquals("rw-------", perms(f), f.getFileName().toString());
                assertFalse(new String(Files.readAllBytes(f), StandardCharsets.ISO_8859_1).contains("PRIVATE KEY"), "no PEM key on disk: " + f);
            }
        }
        assertTrue(Files.exists(dir.resolve("client.p12")));
        assertTrue(h.core.clientSans.stream().allMatch(s -> s.equals(h.tt.enrollment().sourceId)), "mTLS identity is the source id");
    }

    static String perms(Path p) throws Exception {
        Set<PosixFilePermission> s = Files.getPosixFilePermissions(p);
        return java.nio.file.attribute.PosixFilePermissions.toString(s);
    }

    @Test
    @Order(1)
    void inboundAndOutboundExchangesBecomeSanitizedCorrelatedEvents() throws Exception {
        int before = h.core.events.size();
        String tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        HttpResponse<String> r = h.call("POST", "/orders?promo=AUTUMN10",
            Map.of("content-type", "application/json", "cookie", "sid=9f8e7d6c5b4a", "traceparent", tp), Harness.ORDER_BODY);
        assertEquals(201, r.statusCode());
        assertTrue(r.body().startsWith("{\"id\":\"ORD-2026-000184\",\"status\":\"CREATED\",\"total\":73.40"), r.body());
        assertTrue(r.headers().allValues("set-cookie").stream().anyMatch(c -> c.startsWith("cart=abc123def456")), "app cookies unchanged");
        assertTrue(h.waitEvents(before + 3), "three events arrived: " + h.core.events.size());

        List<Map<String, Object>> evs = h.core.events.subList(before, h.core.events.size()).stream().map(CaptureIntegrationTest::m).toList();
        Map<String, Object> in = evs.stream().filter(e -> e.get("dir").equals("inbound")).findFirst().orElseThrow();
        List<Map<String, Object>> outs = evs.stream().filter(e -> e.get("dir").equals("outbound")).toList();
        assertEquals(2, outs.size());

        assertEquals("tt.http.exchange/v1", in.get("schema"));
        assertEquals("shop-api", in.get("service"));
        assertEquals("POST /orders", in.get("op"));
        assertEquals("policy", in.get("route_source"));
        assertEquals("trace", in.get("sampled_by"));
        assertEquals("201", ((Json.Lex) in.get("status")).lex);
        assertEquals("4bf92f3577b34da6a3ce929d0e0e4736", in.get("trace_id"));
        assertEquals("00f067aa0ba902b7", in.get("parent_span_id"));
        assertTrue(((String) in.get("span_id")).matches("[0-9a-f]{16}"));
        assertEquals("sdk-java", m(in.get("source")).get("kind"));
        assertTrue(((String) m(in.get("source")).get("id")).startsWith("src-"));
        assertEquals("p-shop", m(in.get("policy")).get("id"));
        assertTrue(((String) m(in.get("policy")).get("hash")).matches("sha256:[0-9a-f]{64}"));
        Map<String, Object> req = m(in.get("req"));
        assertEquals(map("email", "drop:str:email", "items", list(map("qty", "drop:int", "sku", "drop:str:l32")), "note", "drop:str:l8"), req.get("body"));
        assertEquals(map("promo", list("drop:str:l8")), req.get("query"));
        assertEquals(map("sid", list("drop:str:l32")), req.get("cookies"));
        assertEquals(list("keep:application/json"), m(req.get("headers")).get("content-type"));
        assertEquals("l128", req.get("size"));
        Map<String, Object> resp = m(in.get("resp"));
        Map<String, Object> rbody = m(resp.get("body"));
        assertTrue(((String) rbody.get("id")).matches("tk1:k1:[A-Za-z0-9_-]{22}"));
        assertEquals("keep:CREATED", rbody.get("status"));
        assertEquals("num:50-100", rbody.get("total"));
        assertEquals("drop:str:email", rbody.get("email"));
        assertEquals(map("cart", list("drop:str:l32")), resp.get("cookies"));

        Map<String, Object> post = outs.stream().filter(e -> e.get("op").equals("POST /v1/shipments")).findFirst().orElseThrow();
        Map<String, Object> get = outs.stream().filter(e -> e.get("op").equals("GET /v1/shipments")).findFirst().orElseThrow();
        for (Map<String, Object> o : List.of(post, get)) {
            assertEquals("carrier", o.get("service"));
            assertEquals("inherited", o.get("sampled_by"));
            assertEquals(in.get("trace_id"), o.get("trace_id"), "outbound shares the inbound trace");
            assertEquals(in.get("span_id"), o.get("parent_span_id"));
        }
        assertEquals(rbody.get("id"), m(m(post.get("req")).get("body")).get("orderId"), "same order id, same token");
        assertEquals("drop:str:email", m(m(post.get("req")).get("body")).get("email"));
        assertEquals("keep:BOOKED", m(m(post.get("resp")).get("body")).get("status"));
        assertEquals("drop:str:l8", m(m(post.get("resp")).get("body")).get("shipmentId"));
        assertEquals(list("drop:str:l32"), m(m(post.get("req")).get("headers")).get("authorization"));
        assertEquals(map("orderId", list(rbody.get("id"))), m(get.get("req")).get("query"));
    }

    @Test
    @Order(2)
    void eventsAreCanonicalCarryNoValueAndTheOtlpEnvelopeFollowsEventMd() {
        assertFalse(h.core.eventStrings.isEmpty());
        for (String s : h.core.eventStrings) {
            assertEquals(s, Json.writeCanonical(Json.plainToOut(Json.parsePlain(s.getBytes(StandardCharsets.UTF_8), false))), "byte-exact canonical form");
            for (String secret : List.of("giulia", "ORD-2026", "TSHIRT", "9f8e7d6c5b4a", "carrier-api-key", "SHP-5521", "AUTUMN10", "abc123def456")) {
                assertFalse(s.contains(secret), "value leaked: " + secret);
            }
        }
        Map<String, Object> doc = h.core.otlpRequests.get(0);
        Map<String, Object> rl = m(l(doc.get("resourceLogs")).get(0));
        Map<String, Object> attrs = new java.util.HashMap<>();
        for (Object a : l(m(rl.get("resource")).get("attributes"))) attrs.put((String) m(a).get("key"), m(m(a).get("value")).get("stringValue"));
        assertEquals("shop-api", attrs.get("service.name"));
        assertEquals("sdk-java", attrs.get("tt.source.kind"));
        Map<String, Object> lr = m(l(m(l(rl.get("scopeLogs")).get(0)).get("logRecords")).get(0));
        assertEquals("tt.http.exchange", lr.get("eventName"));
        assertEquals("9", ((Json.Lex) lr.get("severityNumber")).lex);
        assertTrue(((String) lr.get("timeUnixNano")).matches("[0-9]+"));
    }

    @Test
    @Order(3)
    void theAppTrafficIsUnchanged() {
        assertTrue(h.carrierSeen.size() >= 2);
        for (Harness.Seen s : h.carrierSeen) {
            for (String name : s.headers().keySet()) {
                assertFalse(name.equalsIgnoreCase("traceparent") || name.equalsIgnoreCase("baggage"), "injected header " + name);
            }
        }
        Harness.Seen post = h.carrierSeen.stream().filter(s -> s.method().equals("POST")).findFirst().orElseThrow();
        assertEquals("{\"orderId\":\"ORD-2026-000184\",\"email\":\"giulia.neri@example.com\"}", post.body(), "request body delivered intact");
    }

    @Test
    @Order(4)
    void largeBinaryBodiesPassThroughByteForByteAndReportTruncation() throws Exception {
        int before = h.core.events.size();
        byte[] big = new byte[3 << 20];
        new java.util.Random(7).nextBytes(big);
        HttpRequest rq = HttpRequest.newBuilder(URI.create(h.appUrl("/echo"))).header("content-type", "application/octet-stream")
            .POST(HttpRequest.BodyPublishers.ofByteArray(big)).build();
        HttpResponse<byte[]> r = h.plain.send(rq, HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, r.statusCode());
        assertTrue(java.util.Arrays.equals(big, r.body()), "echo identical");
        assertTrue(h.waitEvents(before + 1));
        Map<String, Object> ev = m(h.core.events.get(before));
        assertEquals("trunc:size", m(ev.get("req")).get("body"));
        assertEquals("lmax", m(ev.get("req")).get("size"));
        assertEquals("trunc:size", m(ev.get("resp")).get("body"));
    }

    @Test
    @Order(5)
    void gzipRequestBodiesAreDecodedByTheSanitizer() throws Exception {
        int before = h.core.events.size();
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try (GZIPOutputStream g = new GZIPOutputStream(bo)) {
            g.write("{\"a\":1,\"b\":\"secret-value-xyz\"}".getBytes(StandardCharsets.UTF_8));
        }
        HttpRequest rq = HttpRequest.newBuilder(URI.create(h.appUrl("/echo"))).header("content-type", "application/json")
            .header("content-encoding", "gzip").POST(HttpRequest.BodyPublishers.ofByteArray(bo.toByteArray())).build();
        assertEquals(200, h.plain.send(rq, HttpResponse.BodyHandlers.ofByteArray()).statusCode());
        assertTrue(h.waitEvents(before + 1));
        Map<String, Object> ev = m(h.core.events.get(before));
        assertEquals(map("a", "drop:int", "b", "drop:str:l32"), m(ev.get("req")).get("body"));
        assertFalse(h.core.eventStrings.get(before).contains("secret-value-xyz"));
    }

    @Test
    @Order(6)
    void aBodyThatTheAppDoesNotReadIsNotConsumed() throws Exception {
        int before = h.core.events.size();
        HttpRequest rq = HttpRequest.newBuilder(URI.create(h.appUrl("/echo"))).header("content-type", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString("{\"password\":\"hunter2-hunter2\"}")).build();
        assertEquals(204, h.plain.send(rq, HttpResponse.BodyHandlers.discarding()).statusCode());
        assertTrue(h.waitEvents(before + 1));
        Map<String, Object> ev = m(h.core.events.get(before));
        assertEquals("trunc:size", m(ev.get("req")).get("body"));
        assertFalse(h.core.eventStrings.get(before).contains("hunter2"));
    }

    @Test
    @Order(7)
    void springMvcBestMatchingPatternGivesTheFrameworkRoute() throws Exception {
        int before = h.core.events.size();
        HttpResponse<String> r = h.call("GET", "/orders/ORD-2026-000184", Map.of(), null);
        assertEquals(200, r.statusCode());
        assertTrue(h.waitEvents(before + 1));
        Map<String, Object> ev = m(h.core.events.get(before));
        assertEquals("GET /orders/{id}", ev.get("op"));
        assertEquals("framework", ev.get("route_source"));
        assertTrue(((String) m(ev.get("req")).get("path")).matches("/orders/\\{tk1:k1:[A-Za-z0-9_-]{22}}"), (String) m(ev.get("req")).get("path"));
        assertFalse(h.core.eventStrings.get(before).contains("ORD-2026"));
    }

    @Test
    @Order(7)
    void theSpringPatternIsCompletedWithTheServletPathOfAPrefixMapping() throws Exception {
        int before = h.core.events.size();
        assertEquals(200, h.call("GET", "/api/orders/ORD-2026-000184", Map.of(), null).statusCode());
        assertTrue(h.waitEvents(before + 1));
        Map<String, Object> ev = m(h.core.events.get(before));
        assertEquals("GET /api/orders/{id}", ev.get("op"));
        assertEquals("framework", ev.get("route_source"));
    }

    @Test
    @Order(8)
    void asyncServletsAreCapturedWhenTheyComplete() throws Exception {
        int before = h.core.events.size();
        HttpResponse<String> r = h.call("GET", "/async", Map.of(), null);
        assertEquals("{\"async\":true}", r.body());
        assertTrue(h.waitEvents(before + 1));
        Map<String, Object> ev = m(h.core.events.get(before));
        assertEquals(map("async", "drop:bool"), m(ev.get("resp")).get("body"));
    }

    @Test
    @Order(9)
    void heartbeatReportsCountersAndOverheadNeverValues() throws Exception {
        assertTrue(h.core.waitFor(c -> {
            var hb = c.heartbeats.get(c.heartbeats.size() - 1);
            return Double.parseDouble(((Json.Lex) m(hb.get("counters")).get("events_sent")).lex) >= 3;
        }, 10_000));
        Map<String, Object> hb = m(h.core.heartbeats.get(h.core.heartbeats.size() - 1));
        assertEquals("capturing", hb.get("state"));
        assertEquals("0", ((Json.Lex) m(hb.get("counters")).get("sanitizer_errors")).lex);
        assertEquals("p-shop", m(hb.get("policy")).get("id"));
        assertNotNull(hb.get("overhead_us"));
        assertFalse(Json.writeCanonical(Json.plainToOut(hb)).contains("giulia"));
    }

    @Test
    @Order(10)
    void killSwitchStopsCaptureAndTurningItOffResumesIt() throws Exception {
        h.core.kill = true;
        assertTrue(h.core.waitFor(c -> c.lastHeartbeatState().equals("killed"), 10_000));
        int n = h.core.events.size();
        HttpResponse<String> r = h.call("POST", "/orders", Map.of("content-type", "application/json"), "{\"email\":\"a@b.example\"}");
        assertEquals(201, r.statusCode(), "the app keeps working");
        Thread.sleep(700);
        assertEquals(n, h.core.events.size(), "no events while killed");
        h.core.kill = false;
        assertTrue(h.core.waitFor(c -> c.lastHeartbeatState().equals("capturing"), 10_000));
    }

    @Test
    @Order(11)
    void aPolicyBelowMinIssuedSeqIsRejectedFailClosedAndANewerOneRecovers() throws Exception {
        h.core.minIssuedSeq = 5;
        assertTrue(h.core.waitFor(c -> c.lastHeartbeatState().equals("policy_rejected"), 10_000), h.core.lastHeartbeatState());
        assertNull(h.tt.active(), "no capture while rejected");
        Map<String, Object> fresh = h.policy();
        fresh.put("issued_seq", 6L);
        fresh.put("version", 2L);
        h.core.setPolicy(fresh);
        assertTrue(h.core.waitFor(c -> c.lastHeartbeatState().equals("capturing")
            && ((Json.Lex) m(c.heartbeats.get(c.heartbeats.size() - 1).get("policy")).get("issued_seq")).lex.equals("6"), 10_000));
    }

    // Usability test 4: tt-core moves min_issued_seq to the new policy in the same heartbeat that
    // announces it; the source switches without an error or a policy_rejected state.
    @Test
    @Order(12)
    void aNormalPolicyChangeReportsNoError() throws Exception {
        int from = h.core.heartbeats.size();
        String since = java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString();
        for (long seq = 7; seq <= 9; seq++) {
            Map<String, Object> next = h.policy();
            next.put("issued_seq", seq);
            next.put("version", seq);
            h.core.setPolicy(next);
            h.core.minIssuedSeq = seq;
            String want = Long.toString(seq);
            assertTrue(h.core.waitFor(c -> c.lastHeartbeatState().equals("capturing") && c.heartbeats.get(c.heartbeats.size() - 1).get("policy") != null
                && ((Json.Lex) m(c.heartbeats.get(c.heartbeats.size() - 1).get("policy")).get("issued_seq")).lex.equals(want), 10_000), "switched to " + seq);
        }
        List<Map<String, Object>> hbs = h.core.heartbeats.subList(from, h.core.heartbeats.size());
        for (Map<String, Object> hb : hbs) assertNotEquals("policy_rejected", String.valueOf(hb.get("state")));
        Object errs = hbs.get(hbs.size() - 1).get("last_errors");
        if (errs instanceof List<?> l) {
            for (Object e : l) {
                Map<?, ?> em = (Map<?, ?>) e;
                if (String.valueOf(em.get("at")).compareTo(since) < 0) continue;
                String code = String.valueOf(em.get("code"));
                assertNotEquals("policy_below_min_issued_seq", code);
                assertNotEquals("policy_rejected", code);
            }
        }
    }

    @Test
    @Order(12)
    void exportRetriesOn503() throws Exception {
        h.core.failLogs = 1;
        int before = h.core.events.size();
        h.call("GET", "/async", Map.of(), null);
        assertTrue(h.waitEvents(before + 1), "delivered after a 503 with Retry-After");
    }

    @Test
    @Order(8)
    void aJsonBodyReadUpToItsClosingBraceIsConsumedWithContentLengthAndChunked() throws Exception {
        for (boolean chunked : new boolean[] {false, true}) {
            int before = h.core.events.size();
            HttpRequest.BodyPublisher body = HttpRequest.BodyPublishers.ofString(Harness.ORDER_BODY);
            if (chunked) body = HttpRequest.BodyPublishers.fromPublisher(body); // no length: Transfer-Encoding: chunked
            HttpRequest rq = HttpRequest.newBuilder(URI.create(h.appUrl("/parse"))).header("content-type", "application/json").POST(body).build();
            assertEquals(200, h.plain.send(rq, HttpResponse.BodyHandlers.discarding()).statusCode());
            assertTrue(h.waitEvents(before + 1));
            Map<String, Object> req = m(m(h.core.events.get(before)).get("req"));
            assertEquals(map("email", "drop:str:email", "items", list(map("qty", "drop:int", "sku", "drop:str:l32")), "note", "drop:str:l8"), req.get("body"), chunked ? "chunked" : "content-length");
            assertEquals("l128", req.get("size"), chunked ? "chunked" : "content-length");
        }
    }

    @Test
    @Order(8)
    void aBodyOnlyPartlyReadIsStillNotConsumedWithContentLengthAndChunked() throws Exception {
        for (boolean chunked : new boolean[] {false, true}) {
            int before = h.core.events.size();
            HttpRequest.BodyPublisher body = HttpRequest.BodyPublishers.ofString(Harness.ORDER_BODY);
            if (chunked) body = HttpRequest.BodyPublishers.fromPublisher(body);
            // The application reads the first 40 bytes only: an incomplete document, whatever the framing.
            HttpRequest rq = HttpRequest.newBuilder(URI.create(h.appUrl("/parse?stopAfter=40"))).header("content-type", "application/json").POST(body).build();
            assertEquals(200, h.plain.send(rq, HttpResponse.BodyHandlers.discarding()).statusCode());
            assertTrue(h.waitEvents(before + 1));
            Map<String, Object> req = m(m(h.core.events.get(before)).get("req"));
            assertEquals("trunc:size", req.get("body"), chunked ? "chunked" : "content-length");
            assertFalse(h.core.eventStrings.get(before).contains("TSHIRT"));
        }
    }
}
