package io.github.ivseb.traffictwin.sanitizer;

import io.github.ivseb.traffictwin.sanitizer.Exchange.Header;
import io.github.ivseb.traffictwin.sanitizer.Json.Lex;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Executes one conformance vector (conformance/format.md, "Executing a vector"). This is the
 * test function every source must expose (sanitizer.md 16).
 */
public final class VectorRunner {
    private VectorRunner() {}

    /** Result of a vector: event (canonical bytes), not_sampled (reason) or refused (code). */
    public record VectorResult(String outcome, String canonical, String sampledBy, String code) {
        @Override
        public String toString() {
            return switch (outcome) {
                case "event" -> canonical;
                case "not_sampled" -> "not_sampled/" + sampledBy;
                default -> "refused/" + code;
            };
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object v) {
        return v instanceof Map<?, ?> ? (Map<String, Object>) v : null;
    }

    private static byte[] bytes(Object v) {
        if (v == null) return new byte[0];
        if (v instanceof String s) return s.getBytes(StandardCharsets.UTF_8);
        Map<String, Object> m = obj(v);
        if (m != null && m.get("b64") instanceof String b) return Base64.getDecoder().decode(b);
        throw new IllegalArgumentException("bad bytes value");
    }

    private static long total(Object v) {
        if ("unknown".equals(v)) return Exchange.UNKNOWN;
        if (v instanceof Lex l) return (long) Double.parseDouble(l.lex);
        return Exchange.ABSENT;
    }

    private static boolean bool(Object v, boolean d) {
        return v instanceof Boolean b ? b : d;
    }

    private static List<Header> headers(Object v) {
        List<Header> out = new ArrayList<>();
        if (v instanceof List<?> l) {
            for (Object pair : l) {
                List<?> p = (List<?>) pair;
                out.add(new Header((String) p.get(0), bytes(p.get(1))));
            }
        }
        return out;
    }

    /** Converts the {@code input} object of a vector into a sanitizer exchange. */
    public static Exchange exchange(Map<String, Object> in) {
        Exchange ex = new Exchange();
        ex.inbound = "inbound".equals(in.get("dir"));
        ex.method = in.get("method") instanceof String s ? s : "";
        ex.rawPath = bytes(in.get("raw_path"));
        ex.rawQuery = in.containsKey("raw_query") ? bytes(in.get("raw_query")) : null;
        ex.reqHeaders = headers(in.get("req_headers"));
        ex.reqBody = bytes(in.get("req_body"));
        ex.reqBodyTotal = total(in.get("req_body_total"));
        ex.reqBodyConsumed = bool(in.get("req_body_consumed"), true);
        ex.reqBodyDecoded = bool(in.get("req_body_decoded"), false);
        ex.respHeaders = headers(in.get("resp_headers"));
        ex.respBody = bytes(in.get("resp_body"));
        ex.respBodyTotal = total(in.get("resp_body_total"));
        ex.respBodyConsumed = bool(in.get("resp_body_consumed"), true);
        ex.respBodyDecoded = bool(in.get("resp_body_decoded"), false);
        if (in.get("service_name") instanceof String s) ex.serviceName = s;
        if (in.get("url_base") instanceof String s) ex.urlBase = s;
        if (in.get("framework_route") instanceof String s) ex.frameworkRoute = s;
        if (in.get("framework") instanceof String s) ex.framework = s;
        if (in.get("trace_id") instanceof String s) ex.traceId = s;
        if (in.get("inherited") instanceof Boolean b) ex.inherited = b;
        if (in.get("status") instanceof Lex l) ex.status = (int) Double.parseDouble(l.lex);
        if (in.get("net_error") instanceof String s) ex.netError = s;
        return ex;
    }

    /** Parses a vector file with the lexeme-preserving parser. */
    public static Map<String, Object> parse(byte[] bytes) {
        return obj(Json.parsePlain(bytes, false));
    }

    private static long lng(Object v, long d) {
        return v instanceof Lex l ? (long) Double.parseDouble(l.lex) : d;
    }

    /** Runs one parsed vector. {@code conformanceDir} is the conformance/ directory (for policy_ref). */
    public static VectorResult run(Map<String, Object> vec, Path conformanceDir) throws IOException {
        double now = vec.get("now") instanceof String s ? Policy.parseTime(s) : Double.NaN;
        Sanitizer sanitizer;
        try {
            Map<String, Object> body;
            if (vec.get("policy_envelope") != null) {
                Map<String, PublicKey> keys = new HashMap<>();
                Map<String, Object> fk = obj(vec.get("fleet_keys"));
                if (fk != null) {
                    for (Map.Entry<String, Object> e : fk.entrySet()) {
                        PublicKey k = Ed25519.publicKey((String) e.getValue());
                        if (k != null) keys.put(e.getKey(), k);
                    }
                }
                body = Envelope.verify(vec.get("policy_envelope"), keys, true).body();
            } else if (vec.get("policy_ref") instanceof String ref) {
                body = PolicyValidator.validate(strictBody(Files.readAllBytes(conformanceDir.resolve(ref))));
            } else if (vec.get("policy") != null) {
                body = PolicyValidator.validate(vec.get("policy"));
            } else {
                throw new Refused("no_policy");
            }
            Policy policy = new Policy(body);
            Envelope.checkAcceptance(policy, vec.get("source_group") instanceof String g ? g : "", Double.isNaN(now) ? Double.NaN : now,
                lng(vec.get("last_issued_seq"), 0), lng(vec.get("min_issued_seq"), 0), false);
            KeyRing ring = KeyRing.parse(vec.get("hmac_key") instanceof String k ? k : null);
            sanitizer = new Sanitizer(policy, ring.select(policy));
        } catch (Refused r) {
            return new VectorResult("refused", null, null, r.code());
        } catch (Json.JsonError e) {
            return new VectorResult("refused", null, null, "policy_rejected");
        }
        Sanitizer.Result r = sanitizer.run(exchange(obj(vec.get("input"))), now, null);
        if (r.outcome.equals("not_sampled")) return new VectorResult("not_sampled", null, r.sampledBy, null);
        if (r.outcome.equals("too_large")) return new VectorResult("refused", null, null, "event_too_large");
        return new VectorResult("event", r.canonical, r.sampledBy, null);
    }

    private static Object strictBody(byte[] file) {
        return Json.parsePlain(file, true);
    }
}
