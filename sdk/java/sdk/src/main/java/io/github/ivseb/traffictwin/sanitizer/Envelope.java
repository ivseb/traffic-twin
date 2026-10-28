package io.github.ivseb.traffictwin.sanitizer;

import io.github.ivseb.traffictwin.sanitizer.Json.Lex;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;

/** Signed envelope {@code tt.policy.compiled/v1} (policy.md 3) and source acceptance (policy.md 4). */
public final class Envelope {
    private Envelope() {}

    public static final String FORMAT = "tt.policy.compiled/v1";
    private static final byte[] SIGNATURE_PREFIX = "tt.policy.body/v1\0".getBytes(StandardCharsets.ISO_8859_1);

    public record Verified(byte[] bodyBytes, Map<String, Object> body, String hash) {}

    public static String sha256Hex(byte[] b) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Refused reject(String why) {
        return new Refused("policy_rejected", why);
    }

    private static boolean same(Object a, Object b) {
        if (a instanceof Lex x && b instanceof Lex y) return x.lex.equals(y.lex);
        return a == null ? b == null : a.equals(b);
    }

    /**
     * Verifies an envelope (policy.md 3-4 conditions 1-2). {@code keys} maps a pinned,
     * non-revoked signature kid to its public key. {@code strict} applies the full body schema
     * (production); otherwise only the minimal checks of the conformance runner.
     */
    @SuppressWarnings("unchecked")
    public static Verified verify(Object env, Map<String, PublicKey> keys, boolean strict) {
        if (!(env instanceof Map<?, ?>)) throw reject("envelope");
        Map<String, Object> e = (Map<String, Object>) env;
        if (strict) {
            Set<String> allowed = Set.of("format", "policy_id", "version", "issued_seq", "hash", "body_b64", "signature");
            for (String k : e.keySet()) if (!allowed.contains(k)) throw reject("envelope field");
        }
        if (!FORMAT.equals(e.get("format"))) throw reject("envelope format");
        if (!(e.get("signature") instanceof Map<?, ?>)) throw reject("signature");
        Map<String, Object> sig = (Map<String, Object>) e.get("signature");
        if (!"Ed25519".equals(sig.get("alg")) || !(sig.get("kid") instanceof String kid) || !(sig.get("sig") instanceof String sigStr)) {
            throw reject("signature");
        }
        PublicKey pub = keys.get(kid);
        if (pub == null) throw reject("unknown kid");
        if (!(e.get("body_b64") instanceof String b64)) throw reject("body_b64");
        byte[] bodyBytes = Base64Url.decodeStrict(b64);
        if (bodyBytes == null || bodyBytes.length == 0) throw reject("body_b64");
        String hash = "sha256:" + sha256Hex(bodyBytes);
        if (!hash.equals(e.get("hash"))) throw reject("hash");
        byte[] sigBytes = Base64Url.decodeStrict(sigStr);
        if (sigBytes == null || sigBytes.length != 64) throw reject("signature encoding");
        byte[] msg = new byte[SIGNATURE_PREFIX.length + bodyBytes.length];
        System.arraycopy(SIGNATURE_PREFIX, 0, msg, 0, SIGNATURE_PREFIX.length);
        System.arraycopy(bodyBytes, 0, msg, SIGNATURE_PREFIX.length, bodyBytes.length);
        if (!Ed25519.verify(pub, msg, sigBytes)) throw reject("signature");
        Object plain;
        try {
            plain = Json.parsePlain(bodyBytes, true);
        } catch (Json.JsonError err) {
            throw reject("body json");
        }
        Map<String, Object> body = strict ? PolicyValidator.validate(plain) : PolicyValidator.checkMinimal(plain);
        if (!same(e.get("policy_id"), body.get("policy_id"))) throw reject("policy_id mismatch");
        if (!same(e.get("version"), body.get("version"))) throw reject("version mismatch");
        if ((strict || e.get("issued_seq") != null || body.get("issued_seq") != null) && !same(e.get("issued_seq"), body.get("issued_seq"))) {
            throw reject("issued_seq mismatch");
        }
        if (strict && !Policy.BODY_FORMAT.equals(body.get("format"))) throw reject("body format");
        PolicyValidator.checkMinimal(body);
        return new Verified(bodyBytes, body, hash);
    }

    /**
     * policy.md 4, conditions 3-5: group, expiry, issued_seq ordering. {@code allowEqualSeq} lets a
     * source re-verify the very policy it already accepted (cache at start-up).
     */
    public static void checkAcceptance(Policy p, String group, double now, long lastIssuedSeq, long minIssuedSeq, boolean allowEqualSeq) {
        if (!p.groups.contains(group)) throw new Refused("policy_rejected", "group");
        if (!(now < p.notAfter)) throw new Refused("expired_policy");
        boolean fresh = allowEqualSeq ? p.issuedSeq >= lastIssuedSeq : p.issuedSeq > lastIssuedSeq;
        if (!fresh) throw new Refused("policy_rejected", "issued_seq replay");
        if (p.issuedSeq < minIssuedSeq) throw new Refused("policy_rejected", "issued_seq below minimum");
    }
}
