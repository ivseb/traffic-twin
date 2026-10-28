package io.github.ivseb.traffictwin;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.ivseb.traffictwin.sanitizer.Json;
import io.github.ivseb.traffictwin.sanitizer.PolicyValidator;
import io.github.ivseb.traffictwin.sanitizer.Refused;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.Test;

/** v1.3 source-side safety subset (docs/spec/hardening.md 2.1): H1, H2, H3. */
class SafetySubsetTest {
    static final String CREATED = "2026-10-20T08:00:00Z";

    static String body(String global, String services, String segments, String discovery) {
        return "{\"format\":\"tt.policy.body/v1\",\"policy_id\":\"p-shop\",\"version\":1,\"issued_seq\":1,"
            + "\"created_at\":\"" + CREATED + "\",\"not_after\":\"2026-11-19T08:00:00Z\","
            + "\"targets\":{\"groups\":[\"shop\"]},\"hmac\":{\"kid\":\"k1\",\"accept_kids\":[],\"epoch\":\"2026-10\"},"
            + "\"sampling\":{\"rate_bp\":10000,\"trust_baggage\":false,\"propagate_to\":[]},"
            + "\"segments\":" + segments + ","
            + "\"limits\":{\"max_body_bytes\":1048576,\"max_depth\":32,\"max_array\":32,\"max_keys\":256,\"keep_max_bytes\":64},"
            + (discovery.isEmpty() ? "" : "\"discovery\":" + discovery + ",")
            + "\"global\":" + global + ",\"services\":" + services + "}";
    }

    static String outcome(String json) {
        try {
            PolicyValidator.validate(Json.parsePlain(json.getBytes(StandardCharsets.UTF_8), true));
            return "accepted";
        } catch (Refused r) {
            return r.isUnsafe() ? "unsafe" : r.code();
        }
    }

    static final String SEG = "{\"auto_words\":false,\"allow\":[],\"hosts_allow\":[]}";
    static final String SVC_HEAD = "{\"name\":\"shop-api\",\"match\":{\"inbound\":true,\"internal\":false}";

    @Test
    void h1CredentialHeaders() {
        for (String h : new String[] {"authorization", "cookie", "set-cookie", "proxy-authorization"}) {
            for (String act : new String[] {"{\"action\":\"keep\"}", "{\"action\":\"hmac\",\"domain\":\"tok\"}"}) {
                String rule = "{\"headers\":{\"" + h + "\":" + act + "}}";
                String what = h + " " + act;
                assertEquals("unsafe", outcome(body("{\"request\":" + rule + "}", "[]", SEG, "")), "global request " + what);
                assertEquals("unsafe", outcome(body("{\"response\":" + rule + "}", "[]", SEG, "")), "global response " + what);
                assertEquals("unsafe", outcome(body("{\"errors\":" + rule + "}", "[]", SEG, "")), "global errors " + what);
                assertEquals("unsafe", outcome(body("{}", "[" + SVC_HEAD + ",\"errors\":" + rule + ",\"ops\":[]}]", SEG, "")), "service errors " + what);
                assertEquals("unsafe", outcome(body("{}", "[" + SVC_HEAD + ",\"ops\":[{\"op\":\"GET /a\",\"request\":" + rule + "}]}]", SEG, "")), "op request " + what);
                assertEquals("unsafe", outcome(body("{}", "[" + SVC_HEAD + ",\"ops\":[{\"op\":\"GET /a\",\"response\":" + rule + "}]}]", SEG, "")), "op response " + what);
            }
        }
        assertEquals("accepted", outcome(body("{\"request\":{\"headers\":{\"authorization\":{\"action\":\"drop\"}}}}", "[]", SEG, "")));
    }

    @Test
    void h2GlobalStar() {
        String keep = "{\"response\":{\"body\":[{\"path\":\"$.a.*\",\"action\":{\"action\":\"keep\"}}]}}";
        String hmac = "{\"response\":{\"body\":[{\"path\":\"$.items[*].*\",\"action\":{\"action\":\"hmac\",\"domain\":\"tok\"}}]}}";
        String drop = "{\"response\":{\"body\":[{\"path\":\"$.a.*\",\"action\":{\"action\":\"drop\"}}]}}";
        assertEquals("unsafe", outcome(body(keep, "[]", SEG, "")));
        assertEquals("unsafe", outcome(body(hmac, "[]", SEG, "")));
        assertEquals("accepted", outcome(body(drop, "[]", SEG, "")));
        String rule = "{\"body\":[{\"path\":\"$.*\",\"action\":{\"action\":\"keep\"}}]}";
        assertEquals("accepted", outcome(body("{}", "[" + SVC_HEAD + ",\"request\":" + rule + ",\"ops\":[]}]", SEG, "")));
        assertEquals("accepted", outcome(body("{}", "[" + SVC_HEAD + ",\"ops\":[{\"op\":\"GET /a\",\"response\":" + rule + "}]}]", SEG, "")));
    }

    @Test
    void h3Windows() {
        Instant created = Instant.parse(CREATED);
        for (long extra : new long[] {0, 1}) {
            String when = created.plus(7, ChronoUnit.DAYS).plusSeconds(extra).toString();
            String expect = extra == 0 ? "accepted" : "unsafe";
            assertEquals(expect, outcome(body("{}", "[]", SEG, "{\"enabled\":true,\"expires_at\":\"" + when + "\"}")), "discovery +" + extra);
            String seg = "{\"auto_words\":true,\"auto_words_expires_at\":\"" + when + "\",\"allow\":[],\"hosts_allow\":[]}";
            assertEquals(expect, outcome(body("{}", "[]", seg, "")), "auto_words +" + extra);
        }
        assertEquals("accepted", outcome(body("{}", "[]", SEG, "{\"enabled\":false,\"expires_at\":\"2026-12-20T08:00:00Z\"}")));
    }
}
