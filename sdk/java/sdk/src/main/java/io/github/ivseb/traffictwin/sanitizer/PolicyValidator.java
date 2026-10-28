package io.github.ivseb.traffictwin.sanitizer;

import io.github.ivseb.traffictwin.sanitizer.Json.Lex;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Validation of a compiled policy body (policy.md 4 condition 1, schema
 * {@code policy-compiled.v1#/$defs/body}): a source does not trust the validation of tt-core.
 * Any failure is {@code policy_rejected}.
 */
public final class PolicyValidator {
    private PolicyValidator() {}

    private static final class SchemaError extends RuntimeException {
        private static final long serialVersionUID = 1L;

        SchemaError(String m) {
            super(m, null, false, false);
        }
    }

    @FunctionalInterface
    private interface V {
        void check(Object v, String at);
    }

    private static void fail(String at, String why) {
        throw new SchemaError(at + ": " + why);
    }

    private static boolean isObj(Object v) {
        return v instanceof Map<?, ?>;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asObj(Object v) {
        return (Map<String, Object>) v;
    }

    private static V str(String re) {
        Pattern p = Pattern.compile(re);
        return (v, at) -> {
            if (!(v instanceof String s) || !p.matcher(s).matches()) fail(at, "string");
        };
    }

    private static V integer(long min, double max) {
        return (v, at) -> {
            if (!(v instanceof Lex l) || !Json.isIntLexeme(l.lex)) {
                fail(at, "integer");
                return;
            }
            double n = Double.parseDouble(((Lex) v).lex);
            if (n < min || n > max) fail(at, "range");
        };
    }

    private static final double SAFE = 9007199254740991d;
    private static final V BOOL = (v, at) -> {
        if (!(v instanceof Boolean)) fail(at, "boolean");
    };
    private static final V TIME = (v, at) -> {
        if (Double.isNaN(Policy.parseTime(v))) fail(at, "date-time");
    };
    private static final V ANY = (v, at) -> {};

    private static V constStr(String c) {
        return (v, at) -> {
            if (!c.equals(v)) fail(at, "const");
        };
    }

    private static V arr(V item, int max, boolean unique, int min) {
        return (v, at) -> {
            if (!(v instanceof List<?> l) || l.size() > max || l.size() < min) {
                fail(at, "array");
                return;
            }
            Set<String> seen = new HashSet<>();
            List<?> list = (List<?>) v;
            for (int i = 0; i < list.size(); i++) {
                Object x = list.get(i);
                item.check(x, at + "[" + i + "]");
                if (unique) {
                    String k = x instanceof Lex lx ? "n:" + lx.lex : "s:" + x;
                    if (!seen.add(k)) fail(at, "unique");
                }
            }
        };
    }

    private static V object(Map<String, V> props, String... required) {
        return (v, at) -> {
            if (!isObj(v)) {
                fail(at, "object");
                return;
            }
            Map<String, Object> m = asObj(v);
            for (Map.Entry<String, Object> e : m.entrySet()) {
                V p = props.get(e.getKey());
                if (p == null) fail(at + "." + e.getKey(), "unexpected");
                else p.check(e.getValue(), at + "." + e.getKey());
            }
            for (String r : required) if (!m.containsKey(r)) fail(at + "." + r, "required");
        };
    }

    /** identity.subject; spec v1.18: json_path reads a header only and excludes jwt_claim. */
    private static V subject() {
        V base = object(props(
            "from", str("(header|cookie)"),
            "name", str("[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}"),
            "jwt_claim", str(RE_KEYNAME),
            "json_path", str("[A-Za-z0-9_-]{1,64}(\\.[A-Za-z0-9_-]{1,64}){0,7}")), "from", "name");
        return (v, at) -> {
            base.check(v, at);
            Map<String, Object> m = asObj(v);
            if (m.containsKey("json_path") && (m.containsKey("jwt_claim") || !"header".equals(m.get("from")))) {
                fail(at + ".json_path", "header only, excludes jwt_claim");
            }
        };
    }

    private static V nameMap(String nameRe, V val, int max) {
        Pattern p = Pattern.compile(nameRe);
        return (v, at) -> {
            if (!isObj(v)) {
                fail(at, "object");
                return;
            }
            Map<String, Object> m = asObj(v);
            if (m.size() > max) fail(at, "maxProperties");
            for (Map.Entry<String, Object> e : m.entrySet()) {
                if (!p.matcher(e.getKey()).matches()) fail(at + "." + e.getKey(), "name");
                val.check(e.getValue(), at + "." + e.getKey());
            }
        };
    }

    private static Map<String, V> props(Object... kv) {
        Map<String, V> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], (V) kv[i + 1]);
        return m;
    }

    private static final String RE_POLICY_ID = "[a-z0-9][a-z0-9-]{0,62}";
    private static final String RE_DOMAIN = "[a-z][a-z0-9_-]{0,31}";
    private static final String RE_KID = "[a-z0-9]{1,8}";
    private static final String RE_HOSTPORT = "[a-z0-9.-]{1,253}(:[0-9]{1,5})?";
    private static final String RE_KEYNAME = "[A-Za-z_][A-Za-z0-9_.-]{0,63}";
    private static final String RE_HEADERNAME = "[a-z0-9!#$%&'*+.^_`|~-]{1,64}";
    private static final String RE_PARAMNAME = "[A-Za-z_][A-Za-z0-9_]{0,63}";
    // v1.19: also ".@name" and ".#text" (XML attributes and mixed text, sanitizer.md 5.0).
    private static final String RE_TTPATH = "\\$(\\.@?[A-Za-z_][A-Za-z0-9_-]{0,63}|\\.#text|\\.\\*|\\[\\*\\]){0,64}";
    private static final String SEG = "([A-Za-z0-9._~-]{1,64}|\\{[A-Za-z_][A-Za-z0-9_]{0,63}\\})";
    private static final String RE_OPKEY = "[A-Z]{1,16} /" + SEG + "?(/" + SEG + "){0,31}";
    private static final String RE_BASE = "https?://[a-z0-9.-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~-]{1,64})*";

    private static final V ACTION = (v, at) -> {
        if (!isObj(v)) {
            fail(at, "action");
            return;
        }
        Map<String, Object> m = asObj(v);
        Object a = m.get("action");
        if ("code".equals(a) && m.containsKey("shape")) {
            // v1.19 (sanitizer.md 5.6): the only shape is "alnum"; no other action takes a shape.
            object(props("action", ANY, "shape", constStr("alnum")), "action", "shape").check(v, at);
            return;
        }
        if ("drop".equals(a) || "keep".equals(a) || "code".equals(a) || "graphql".equals(a)) {
            object(props("action", ANY), "action").check(v, at);
            return;
        }
        if ("hmac".equals(a)) {
            object(props("action", ANY, "domain", str(RE_DOMAIN)), "action", "domain").check(v, at);
            if (Policy.RESERVED_DOMAINS.contains((String) m.get("domain"))) fail(at, "reserved domain");
            return;
        }
        if ("bucket".equals(a) && "num".equals(m.get("kind"))) {
            object(props("action", ANY, "kind", ANY, "bounds", arr((x, a2) -> {
                if (!(x instanceof Lex l)) fail(a2, "number");
                else if (l.lex.length() > 64) fail(a2, "lexeme");
            }, 32, false, 1)), "action", "kind", "bounds").check(v, at);
            List<?> bounds = (List<?>) m.get("bounds");
            double prev = Double.NaN;
            for (int i = 0; i < bounds.size(); i++) {
                double d = Double.parseDouble(((Lex) bounds.get(i)).lex);
                if (i > 0 && !(prev < d)) fail(at, "bounds not increasing");
                prev = d;
            }
            return;
        }
        if ("bucket".equals(a) && "time".equals(m.get("kind"))) {
            object(props("action", ANY, "kind", ANY, "unit", str("(year|month|day|hour)")), "action", "kind", "unit").check(v, at);
            return;
        }
        fail(at, "action");
    };

    private static final V BODY_RULES = arr(object(props("path", str(RE_TTPATH), "action", ACTION), "path", "action"), 1024, false, 0);

    private static final V PART = object(props(
        "query", nameMap(RE_KEYNAME, ACTION, 256),
        "headers", nameMap(RE_HEADERNAME, ACTION, 256),
        "cookies", nameMap(RE_KEYNAME, ACTION, 256),
        "body", BODY_RULES));

    private static final V OP_PART = object(props(
        "path", nameMap(RE_PARAMNAME, ACTION, 32),
        "query", nameMap(RE_KEYNAME, ACTION, 256),
        "headers", nameMap(RE_HEADERNAME, ACTION, 256),
        "cookies", nameMap(RE_KEYNAME, ACTION, 256),
        "body", BODY_RULES));

    private static final V SCOPE = object(props("request", PART, "response", PART, "errors", PART));

    private static final V MATCH = (v, at) -> {
        if (!isObj(v)) {
            fail(at, "match");
            return;
        }
        if (asObj(v).containsKey("base")) {
            object(props("base", str(RE_BASE)), "base").check(v, at);
            return;
        }
        object(props("inbound", (V) (x, a2) -> {
            if (!Boolean.TRUE.equals(x)) fail(a2, "const");
        }, "internal", BOOL), "inbound", "internal").check(v, at);
    };

    private static final V SERVICE = object(props(
        "name", str("[a-z0-9][a-z0-9._-]{0,62}"),
        "match", MATCH,
        "request", PART,
        "response", PART,
        "errors", PART,
        "ops", arr(object(props("op", str(RE_OPKEY), "request", OP_PART, "response", OP_PART), "op"), 4096, false, 0)),
        "name", "match", "ops");

    private static final V BODY = object(props(
        "format", constStr(Policy.BODY_FORMAT),
        "policy_id", str(RE_POLICY_ID),
        "version", integer(1, SAFE),
        "issued_seq", integer(1, SAFE),
        "created_at", TIME,
        "not_after", TIME,
        "targets", object(props("groups", arr(str(RE_POLICY_ID), 256, true, 1)), "groups"),
        "hmac", object(props("kid", str(RE_KID), "accept_kids", arr(str(RE_KID), 4, true, 0), "epoch", str("[A-Za-z0-9._-]{1,32}")),
            "kid", "epoch", "accept_kids"),
        "identity", object(props("subject", subject())),
        "sampling", object(props("rate_bp", integer(0, 10000), "trust_baggage", BOOL, "propagate_to", arr(str(RE_HOSTPORT), 256, true, 0)),
            "rate_bp", "trust_baggage", "propagate_to"),
        "segments", (V) (v, at) -> {
            object(props(
                "auto_words", BOOL,
                "auto_words_expires_at", TIME,
                "allow", arr(str("[A-Za-z0-9._~-]{1,64}"), 1024, true, 0),
                "hosts_allow", arr(str(RE_HOSTPORT), 1024, true, 0)), "auto_words", "allow", "hosts_allow").check(v, at);
            if (isObj(v) && Boolean.TRUE.equals(asObj(v).get("auto_words")) && !asObj(v).containsKey("auto_words_expires_at")) {
                fail(at, "auto_words_expires_at required");
            }
        },
        "limits", object(props(
            "max_body_bytes", integer(0, 16777216),
            "max_depth", integer(1, 128),
            "max_array", integer(0, 1024),
            "max_keys", integer(1, 4096),
            "keep_max_bytes", integer(0, 1024)),
            "max_body_bytes", "max_depth", "max_array", "max_keys", "keep_max_bytes"),
        "bodies", object(props(
            "xml", BOOL,
            "multipart", BOOL,
            "docs", BOOL,
            "max_large_body_bytes", integer(0, 67108864),
            "large_array", integer(0, 1024),
            "large_nested_array", integer(0, 1024)),
            "xml", "multipart", "docs", "max_large_body_bytes", "large_array", "large_nested_array"),
        "discovery", object(props("enabled", BOOL, "expires_at", TIME), "enabled", "expires_at"),
        "hosts", object(props("discovery", str("(auto|off)")), "discovery"),
        "global", SCOPE,
        "services", arr(SERVICE, 1024, false, 0)),
        "format", "policy_id", "version", "issued_seq", "created_at", "not_after", "targets", "hmac", "sampling", "segments",
        "limits", "global", "services");

    /** Full schema validation of a policy body, plus reserved domains, double bounds and the v1.3 safety subset. */
    public static Map<String, Object> validate(Object body) {
        try {
            BODY.check(body, "$");
        } catch (SchemaError e) {
            throw new Refused("policy_rejected", "schema " + e.getMessage());
        }
        checkUnsafe(asObj(body));
        return asObj(body);
    }

    private static final Set<String> CREDENTIAL_HEADERS = Set.of("authorization", "cookie", "set-cookie", "proxy-authorization");
    private static final double WEEK_MS = 7 * 86_400_000d;

    private static Refused unsafe(String why) {
        return new Refused("policy_rejected", Refused.UNSAFE + ": " + why);
    }

    /**
     * Source-side safety subset (hardening.md 2.1, v1.3), applied to every signed body:
     * H1 keep, code (v1.11, also code(alnum) of v1.19) or hmac on authorization, cookie, set-cookie, proxy-authorization (header rules of request,
     * response and errors; global, services and operations); H2 keep, code or hmac on a tt-path with any wildcard step
     * ({@code .*} or {@code [*]}) in the global body rules; H3 discovery or auto_words expiring later than created_at + 7 days.
     * Properties of the body: neither the clock nor the group matter.
     */
    public static void checkUnsafe(Map<String, Object> b) {
        List<Map<String, Object>> parts = new java.util.ArrayList<>();
        collect(b.get("global"), new String[] {"request", "response", "errors"}, parts);
        if (b.get("services") instanceof List<?> sl) {
            for (Object s : sl) {
                collect(s, new String[] {"request", "response", "errors"}, parts);
                if (isObj(s) && asObj(s).get("ops") instanceof List<?> ol) for (Object o : ol) collect(o, new String[] {"request", "response"}, parts);
            }
        }
        for (Map<String, Object> p : parts) {
            if (!(p.get("headers") instanceof Map<?, ?>)) continue;
            for (Map.Entry<String, Object> h : asObj(p.get("headers")).entrySet()) {
                Object act = isObj(h.getValue()) ? asObj(h.getValue()).get("action") : null;
                if (CREDENTIAL_HEADERS.contains(h.getKey()) && ("keep".equals(act) || "code".equals(act) || "hmac".equals(act))) {
                    throw unsafe(act + " on header " + h.getKey());
                }
            }
        }
        if (isObj(b.get("global"))) {
            Map<String, Object> g = asObj(b.get("global"));
            for (String k : new String[] {"request", "response", "errors"}) {
                if (!isObj(g.get(k)) || !(asObj(g.get(k)).get("body") instanceof List<?> bl)) continue;
                for (Object r : bl) {
                    if (!isObj(r)) continue;
                    Object act = isObj(asObj(r).get("action")) ? asObj(asObj(r).get("action")).get("action") : null;
                    if (("keep".equals(act) || "code".equals(act) || "hmac".equals(act)) && asObj(r).get("path") instanceof String path && (path.contains(".*") || path.contains("[*]"))) {
                        throw unsafe(act + " on " + path + " in a global rule");
                    }
                }
            }
        }
        double limit = Policy.parseTime(b.get("created_at")) + WEEK_MS;
        if (isObj(b.get("segments"))) {
            Map<String, Object> seg = asObj(b.get("segments"));
            if (Boolean.TRUE.equals(seg.get("auto_words")) && Policy.parseTime(seg.get("auto_words_expires_at")) > limit) {
                throw unsafe("auto_words expires beyond created_at + 7 days");
            }
        }
        if (isObj(b.get("discovery"))) {
            Map<String, Object> d = asObj(b.get("discovery"));
            if (Boolean.TRUE.equals(d.get("enabled")) && Policy.parseTime(d.get("expires_at")) > limit) {
                throw unsafe("discovery expires beyond created_at + 7 days");
            }
        }
    }

    /** Minimal body checks of the conformance runner (format.md, step 1), plus the v1.3 safety subset. */
    public static Map<String, Object> checkMinimal(Object body) {
        if (!isObj(body) || !Policy.BODY_FORMAT.equals(asObj(body).get("format"))) throw new Refused("policy_rejected", "body format");
        Map<String, Object> b = asObj(body);
        for (Map<String, Object> a : actions(b)) {
            if ("hmac".equals(a.get("action")) && a.get("domain") instanceof String d && Policy.RESERVED_DOMAINS.contains(d)) {
                throw new Refused("policy_rejected", "reserved domain");
            }
        }
        checkUnsafe(b);
        return b;
    }

    private static List<Map<String, Object>> actions(Map<String, Object> body) {
        List<Map<String, Object>> all = new java.util.ArrayList<>();
        List<Map<String, Object>> parts = new java.util.ArrayList<>();
        collect(body.get("global"), new String[] {"request", "response", "errors"}, parts);
        if (body.get("services") instanceof List<?> sl) {
            for (Object s : sl) {
                collect(s, new String[] {"request", "response", "errors"}, parts);
                if (isObj(s) && asObj(s).get("ops") instanceof List<?> ol) for (Object o : ol) collect(o, new String[] {"request", "response"}, parts);
            }
        }
        for (Map<String, Object> p : parts) {
            for (String sec : new String[] {"query", "headers", "cookies", "path"}) {
                if (p.get(sec) instanceof Map<?, ?>) {
                    for (Object a : asObj(p.get(sec)).values()) if (isObj(a)) all.add(asObj(a));
                }
            }
            if (p.get("body") instanceof List<?> bl) {
                for (Object r : bl) if (isObj(r) && isObj(asObj(r).get("action"))) all.add(asObj(asObj(r).get("action")));
            }
        }
        return all;
    }

    private static void collect(Object scope, String[] keys, List<Map<String, Object>> out) {
        if (!isObj(scope)) return;
        for (String k : keys) if (isObj(asObj(scope).get(k))) out.add(asObj(asObj(scope).get(k)));
    }
}
