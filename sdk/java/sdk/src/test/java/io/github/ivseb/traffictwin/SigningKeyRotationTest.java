package io.github.ivseb.traffictwin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.ivseb.traffictwin.support.FakeCore;
import io.github.ivseb.traffictwin.support.Harness;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Policy signing key rotation over heartbeats: add_signing_keys, revoke_signing_keys, signing_kids. */
class SigningKeyRotationTest {
    static final String K1 = FakeCore.SIGNING_KID;
    static final String K2 = "policy-test-2";

    FakeCore core;
    TrafficTwin tt;
    Path dir;

    @AfterEach
    void tearDown() {
        if (tt != null) tt.stop();
        if (core != null) core.close();
    }

    Config cfg() {
        Config c = new Config();
        c.enrollUrl = core.url;
        c.enrollToken = core.token;
        c.hmacKey = Harness.HMAC_KEY;
        c.serviceName = "shop-api";
        c.stateDir = dir.resolve("s");
        c.exportFlushMs = 100;
        c.heartbeatIntervalMs = 200;
        c.policyPollIntervalMs = 200;
        return c;
    }

    void startCapturing() throws Exception {
        core = new FakeCore(Harness.pki(), FakeCore.basePolicy());
        dir = Files.createTempDirectory("tt-key-rotation-test");
        tt = TrafficTwin.start(cfg());
        tt.ready().get(60, TimeUnit.SECONDS);
        assertTrue(core.waitFor(c -> c.lastHeartbeatState().equals("capturing"), 10_000), core.lastHeartbeatState());
    }

    static Map<String, Object> policyV2() {
        Map<String, Object> p = FakeCore.basePolicy();
        p.put("version", 2L);
        p.put("issued_seq", 2L);
        return p;
    }

    static Object kids(Map<String, Object> hb) {
        return hb.get("signing_kids");
    }

    /** Waits for a heartbeat sent after {@code from} whose signing_kids equals {@code want}. */
    boolean waitKids(int from, List<String> want) throws InterruptedException {
        return core.waitFor(c -> {
            for (int i = from; i < c.heartbeats.size(); i++) if (want.equals(kids(c.heartbeats.get(i)))) return true;
            return false;
        }, 10_000);
    }

    static boolean anySigningKeyError(List<Map<String, Object>> hbs) {
        for (Map<String, Object> hb : hbs) {
            if (hb.get("last_errors") instanceof List<?> l) {
                for (Object e : l) if (e instanceof Map<?, ?> m && String.valueOf(m.get("code")).startsWith("signing_key_")) return true;
            }
        }
        return false;
    }

    @Test
    void aKeyEndorsedByAKidRevokedInTheSameHeartbeatIsNotPinned() throws Exception {
        startCapturing();
        KeyPair k2 = FakeCore.newSigningKey();
        core.revokeSigningKeys = FakeCore.list(K1);
        core.addSigningKeys = FakeCore.list(FakeCore.endorse(K2, k2, K1, core.signer()));
        int hb = core.heartbeats.size();
        // revocation applied before the addition: no key is trusted any more
        assertTrue(waitKids(hb, List.of()), String.valueOf(kids(core.lastHeartbeat())));
        assertNull(tt.policy(), "the policy signed by the revoked kid is dropped");

        // a policy signed by the key endorsed by the revoked kid is never accepted
        int fetches = core.policyFetches;
        core.setPolicy(policyV2(), K2, k2);
        assertTrue(core.waitFor(c -> c.policyFetches > fetches + 1, 10_000));
        int hb2 = core.heartbeats.size();
        assertTrue(core.waitFor(c -> c.heartbeats.size() > hb2 + 1, 10_000));
        assertNull(tt.policy());
        assertNotEquals("capturing", core.lastHeartbeatState());
        assertEquals(List.of(), kids(core.lastHeartbeat()));
        assertTrue(anySigningKeyError(core.heartbeats.subList(hb, core.heartbeats.size())), "the refused addition is reported");
        String state = Files.readString(dir.resolve("s").resolve("state.json"));
        assertFalse(state.contains(K2), state);
    }

    @Test
    void anEndorsedRotationKeepsCapturingThroughTheRevocationOfTheOldKeyAndAcrossRestarts() throws Exception {
        startCapturing();
        assertEquals(List.of(K1), kids(core.heartbeats.get(0)), "the first heartbeat carries the enrollment kid");

        // 1. tt-core endorses a new key with the pinned one
        KeyPair k2 = FakeCore.newSigningKey();
        core.addSigningKeys = FakeCore.list(FakeCore.endorse(K2, k2, K1, core.signer()));
        core.revokeSigningKeys = FakeCore.list();
        int hb = core.heartbeats.size();
        assertTrue(waitKids(hb, List.of(K1, K2)), String.valueOf(kids(core.lastHeartbeat())));

        // 2. a policy signed by the new key is accepted
        String hash = core.setPolicy(policyV2(), K2, k2);
        assertTrue(core.waitFor(c -> tt.policy() != null && hash.equals(tt.policy().hash), 10_000));
        assertTrue(core.waitFor(c -> c.lastHeartbeatState().equals("capturing"), 10_000));

        // 3. the old key is revoked: still capturing with the new one
        core.revokeSigningKeys = FakeCore.list(K1);
        int hb2 = core.heartbeats.size();
        assertTrue(waitKids(hb2, List.of(K2)), String.valueOf(kids(core.lastHeartbeat())));
        int hb3 = core.heartbeats.size();
        assertTrue(core.waitFor(c -> c.heartbeats.size() > hb3 + 1, 10_000));
        assertEquals("capturing", core.lastHeartbeatState());
        assertEquals(hash, tt.policy().hash);
        assertFalse(anySigningKeyError(core.heartbeats), "repeated keys and revocations are not errors");

        // 4. restart: the rotated key and the revocation come from the persisted state alone
        tt.stop();
        core.addSigningKeys = null;
        core.revokeSigningKeys = null;
        int hb4 = core.heartbeats.size();
        tt = TrafficTwin.start(cfg());
        tt.ready().get(60, TimeUnit.SECONDS);
        assertEquals(1, core.enrollments.size(), "no second enrollment");
        assertTrue(core.waitFor(c -> c.heartbeats.size() > hb4 + 1, 10_000));
        for (Map<String, Object> h : core.heartbeats.subList(hb4, core.heartbeats.size())) assertEquals(List.of(K2), kids(h), "heartbeats after the restart");
        assertTrue(core.waitFor(c -> c.lastHeartbeatState().equals("capturing"), 10_000), core.lastHeartbeatState());
        assertEquals(hash, tt.policy().hash);

        // a policy signed by the revoked key is not accepted after the restart
        Map<String, Object> v3 = FakeCore.basePolicy();
        v3.put("version", 3L);
        v3.put("issued_seq", 3L);
        int fetches = core.policyFetches;
        core.setPolicy(v3, K1, core.signer());
        assertTrue(core.waitFor(c -> c.policyFetches > fetches + 1, 10_000));
        assertEquals(hash, tt.policy().hash, "the policy signed by the revoked kid was refused");
    }

    @Test
    void anAlreadyPinnedKeyRepeatedAtEveryHeartbeatIsNoErrorAndNoStateRewrite() throws Exception {
        startCapturing();
        KeyPair k2 = FakeCore.newSigningKey();
        core.addSigningKeys = FakeCore.list(FakeCore.endorse(K2, k2, K1, core.signer()));
        int hb = core.heartbeats.size();
        assertTrue(waitKids(hb, List.of(K1, K2)));
        Path state = dir.resolve("s").resolve("state.json");
        String before = Files.readString(state);
        var mtime = Files.getLastModifiedTime(state);
        int hb2 = core.heartbeats.size();
        assertTrue(core.waitFor(c -> c.heartbeats.size() > hb2 + 3, 10_000));
        assertFalse(anySigningKeyError(core.heartbeats), "the repeated key is skipped silently");
        assertEquals(before, Files.readString(state));
        assertEquals(mtime, Files.getLastModifiedTime(state), "state.json is not rewritten");
        assertEquals(List.of(K1, K2), kids(core.lastHeartbeat()));
    }

    @Test
    void aKidRepeatedWithADifferentKeyIsRefusedAndAChainInOneListIsPinned() throws Exception {
        startCapturing();
        KeyPair k2 = FakeCore.newSigningKey();
        KeyPair k3 = FakeCore.newSigningKey();
        KeyPair evil = FakeCore.newSigningKey();
        // K3 is endorsed by K2, which is pinned earlier in the same list
        core.addSigningKeys = FakeCore.list(FakeCore.endorse(K2, k2, K1, core.signer()), FakeCore.endorse("policy-test-3", k3, K2, k2));
        int hb = core.heartbeats.size();
        assertTrue(waitKids(hb, List.of(K1, K2, "policy-test-3")), String.valueOf(kids(core.lastHeartbeat())));
        assertFalse(anySigningKeyError(core.heartbeats));

        // K2 re-bound to a different key, validly endorsed: refused, the original binding stays
        core.addSigningKeys = FakeCore.list(FakeCore.endorse(K2, evil, K1, core.signer()));
        int hb2 = core.heartbeats.size();
        assertTrue(core.waitFor(c -> anySigningKeyError(c.heartbeats.subList(hb2, c.heartbeats.size())), 10_000));
        int fetches = core.policyFetches;
        core.setPolicy(policyV2(), K2, evil);
        assertTrue(core.waitFor(c -> c.policyFetches > fetches + 1, 10_000));
        assertEquals(1L, tt.policy().issuedSeq, "a policy signed by the conflicting key is refused");
        Map<String, Object> v3 = FakeCore.basePolicy();
        v3.put("version", 3L);
        v3.put("issued_seq", 3L);
        String hash = core.setPolicy(v3, K2, k2);
        assertTrue(core.waitFor(c -> tt.policy() != null && hash.equals(tt.policy().hash), 10_000), "the original K2 still signs");
    }
}
