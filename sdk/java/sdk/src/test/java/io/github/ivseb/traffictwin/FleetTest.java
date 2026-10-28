package io.github.ivseb.traffictwin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.ivseb.traffictwin.export.EventBuilder;
import io.github.ivseb.traffictwin.export.Exporter;
import io.github.ivseb.traffictwin.fleet.FleetClient;
import io.github.ivseb.traffictwin.sanitizer.Base64Url;
import io.github.ivseb.traffictwin.support.FakeCore;
import io.github.ivseb.traffictwin.support.Harness;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Enrollment with the CA pin, policy acceptance, fail-closed states, persistence across restarts, export. */
class FleetTest {
    FakeCore core;
    TrafficTwin tt;
    Path dir;

    @AfterEach
    void tearDown() {
        if (tt != null) tt.stop();
        if (core != null) core.close();
    }

    Config cfg(String key) {
        Config c = new Config();
        c.enrollUrl = core.url;
        c.enrollToken = core.token;
        c.hmacKey = key;
        c.serviceName = "shop-api";
        c.stateDir = dir.resolve("s");
        c.exportFlushMs = 100;
        c.heartbeatIntervalMs = 300;
        c.policyPollIntervalMs = 300;
        return c;
    }

    void init(Map<String, Object> policy) throws Exception {
        core = new FakeCore(Harness.pki(), policy);
        dir = Files.createTempDirectory("tt-fleet-test");
    }

    @Test
    void aWrongCaPinNeverEnrollsAndNeverCaptures() throws Exception {
        init(FakeCore.basePolicy());
        Config c = cfg(Harness.HMAC_KEY);
        c.enrollToken = c.enrollToken.substring(0, c.enrollToken.indexOf('.') + 1) + Base64Url.encode(new byte[32]);
        tt = TrafficTwin.start(c);
        tt.ready().get(30, java.util.concurrent.TimeUnit.SECONDS);
        assertTrue(core.enrollments.isEmpty(), "the token was never sent to an untrusted server");
        assertNull(tt.active());
        assertFalse(tt.state().equals("capturing"));
    }

    @Test
    void aMalformedTokenIsRefusedLocally() {
        FleetClient.FleetException e = org.junit.jupiter.api.Assertions.assertThrows(FleetClient.FleetException.class,
            () -> FleetClient.enroll("https://127.0.0.1:1", "tte_short.pin", new FleetClient.SourceInfo("sdk-java", "0.1.0", "x", null, null, null)));
        assertEquals("enroll_token_malformed", e.code());
    }

    @Test
    void withoutAHmacKeyOrWithAnUnknownKidTheSourceReportsTheStateAndDoesNotCapture() throws Exception {
        init(FakeCore.basePolicy());
        tt = TrafficTwin.start(cfg(null));
        tt.ready().get(60, java.util.concurrent.TimeUnit.SECONDS);
        assertTrue(core.waitFor(c -> c.lastHeartbeatState().equals("key_missing"), 10_000), core.lastHeartbeatState());
        assertNull(tt.active());
        tt.stop();
        TrafficTwin.start(cfg("zz:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"));
        tt = TrafficTwin.current();
        assertTrue(core.waitFor(c -> c.lastHeartbeatState().equals("key_mismatch"), 10_000), core.lastHeartbeatState());
        assertEquals(1, core.enrollments.size(), "the second start reused the stored identity");
    }

    @Test
    void aTamperedPolicyIsRejectedAndNotCached() throws Exception {
        init(FakeCore.basePolicy());
        Map<String, Object> env = core.makeEnvelope(FakeCore.basePolicy());
        String body = (String) env.get("body_b64");
        byte[] raw = Base64Url.decodeStrict(body);
        raw[raw.length - 5] ^= 1; // flip a bit: hash and signature no longer match
        env.put("body_b64", Base64Url.encode(raw));
        core.setPolicy(null);
        // serve the tampered envelope through the real endpoint
        java.lang.reflect.Field f = FakeCore.class.getDeclaredField("envelope");
        f.setAccessible(true);
        f.set(core, env);
        tt = TrafficTwin.start(cfg(Harness.HMAC_KEY));
        tt.ready().get(60, java.util.concurrent.TimeUnit.SECONDS);
        assertTrue(core.waitFor(c -> c.lastHeartbeatState().equals("policy_rejected"), 10_000), core.lastHeartbeatState());
        assertNull(tt.active());
        assertFalse(Files.exists(dir.resolve("s").resolve("policy.envelope.json")), "a rejected policy is never cached");
    }

    @Test
    void restartReusesTheIdentityAndTheCachedPolicyAndKeepsTheKillSwitch() throws Exception {
        init(FakeCore.basePolicy());
        tt = TrafficTwin.start(cfg(Harness.HMAC_KEY));
        tt.ready().get(60, java.util.concurrent.TimeUnit.SECONDS);
        assertTrue(core.waitFor(c -> c.lastHeartbeatState().equals("capturing"), 10_000));
        core.kill = true;
        assertTrue(core.waitFor(c -> c.lastHeartbeatState().equals("killed"), 10_000));
        tt.stop();
        String state = Files.readString(dir.resolve("s").resolve("state.json"));
        assertTrue(state.contains("\"kill\":true"), state);

        core.kill = false;
        int hb = core.heartbeats.size();
        tt = TrafficTwin.start(cfg(Harness.HMAC_KEY));
        tt.ready().get(60, java.util.concurrent.TimeUnit.SECONDS);
        assertEquals(1, core.enrollments.size(), "no second enrollment");
        assertTrue(core.waitFor(c -> c.heartbeats.size() > hb && c.lastHeartbeatState().equals("capturing"), 10_000));
        // The first heartbeat of the new process went out before any capture.
        assertEquals("capturing", tt.state());
    }

    @Test
    void anExpiredPolicyNeverStartsCapturing() throws Exception {
        Map<String, Object> p = FakeCore.basePolicy();
        p.put("not_after", java.time.Instant.now().minusSeconds(60).truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString());
        init(p);
        tt = TrafficTwin.start(cfg(Harness.HMAC_KEY));
        tt.ready().get(60, java.util.concurrent.TimeUnit.SECONDS);
        assertTrue(core.waitFor(c -> c.lastHeartbeatState().equals("expired_policy"), 10_000), core.lastHeartbeatState());
        assertNull(tt.active());
    }

    @Test
    void theExporterQueueIsBoundedAndDropsTheOldestEvents() throws Exception {
        init(FakeCore.basePolicy());
        Exporter.Counters counters = new Exporter.Counters();
        var client = FleetClient.client(io.github.ivseb.traffictwin.fleet.Pki.trustOnly(List.of()));
        Exporter ex = new Exporter(client, URI.create("https://127.0.0.1:9/v1/logs"), "shop-api", "src-1", counters, e -> {}, 3_600_000,
            3, 1 << 20, 0, 10, 10, false);
        for (int i = 0; i < 5; i++) ex.enqueue(new EventBuilder.Queued("{\"n\":" + i + "}", 1000L + i, null, null, "sha256:x"));
        assertEquals(3, ex.size());
        assertEquals(2, counters.eventsDroppedQueue.get());
        ex.clear();
        assertEquals(0, ex.size());
        ex.stop();
    }

    @Test
    void gzipBodiesAreAcceptedByTheIntakeShape() throws Exception {
        init(FakeCore.basePolicy());
        Config c = cfg(Harness.HMAC_KEY);
        c.gzip = true;
        tt = TrafficTwin.start(c);
        tt.ready().get(60, java.util.concurrent.TimeUnit.SECONDS);
        assertTrue(core.waitFor(x -> x.lastHeartbeatState().equals("capturing"), 10_000));
        var exchange = new io.github.ivseb.traffictwin.sanitizer.Exchange();
        exchange.serviceName = "shop-api";
        exchange.method = "GET";
        exchange.rawPath = "/v1/ping".getBytes(StandardCharsets.UTF_8);
        exchange.status = 200;
        var raw = new io.github.ivseb.traffictwin.capture.RawExchange();
        raw.sanitizer = tt.active();
        raw.decision = new io.github.ivseb.traffictwin.sanitizer.Sanitizer.Decision(true, "random");
        raw.inbound = true;
        raw.tsMs = System.currentTimeMillis();
        raw.status = 200;
        raw.build = () -> exchange;
        tt.submit(raw);
        assertTrue(core.waitFor(x -> !x.events.isEmpty(), 10_000));
        assertEquals("gzip", core.gzipSeen);
    }
}
