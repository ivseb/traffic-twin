package io.github.ivseb.traffictwin.sanitizer;

import io.github.ivseb.traffictwin.sanitizer.Json.Lex;
import java.time.DateTimeException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Compiled policy model (policy.md 2): a verified {@code tt.policy.body/v1} ready for the sanitizer. */
public final class Policy {
    public static final String BODY_FORMAT = "tt.policy.body/v1";
    public static final Set<String> RESERVED_DOMAINS = Set.of("subject", "sample", "sample-trace", "discovery");
    private static final double DAY_MS = 86_400_000d;

    // ---------------------------------------------------------------------------------
    // Model

    public record Bound(String canon, double d) {}

    public static final class Action {
        public final String action; // drop | keep | code | hmac | bucket
        public final String domain;
        public final String kind; // num | time
        public final List<Bound> bounds;
        public final String unit;
        /** code only: null (v1.11 shape) or "alnum" (v1.19). */
        public final String shape;

        Action(String action, String domain, String kind, List<Bound> bounds, String unit) {
            this(action, domain, kind, bounds, unit, null);
        }

        Action(String action, String domain, String kind, List<Bound> bounds, String unit, String shape) {
            this.action = action;
            this.domain = domain;
            this.kind = kind;
            this.bounds = bounds;
            this.unit = unit;
            this.shape = shape;
        }

        static final Action DROP = new Action("drop", null, null, null, null);
        static final Action KEEP = new Action("keep", null, null, null, null);
        static final Action CODE = new Action("code", null, null, null, null);
        static final Action CODE_ALNUM = new Action("code", null, null, null, null, "alnum");
        static final Action GRAPHQL = new Action("graphql", null, null, null, null);
    }

    /** One step of a tt-path: a member name, any member (".*") or any element ("[*]"). */
    public record Step(char t, String name) {
        public static final char NAME = 'n';
        public static final char ANY = '*';
        public static final char IDX = 'i';
    }

    public static final class BodyRule {
        public final String path;
        public final Step[] steps;
        public final int names;
        public final Action action;

        BodyRule(String path, Step[] steps, Action action) {
            this.path = path;
            this.steps = steps;
            int c = 0;
            for (Step s : steps) if (s.t() == Step.NAME) c++;
            this.names = c;
            this.action = action;
        }
    }

    public static final class Part {
        public final Map<String, Action> query;
        public final Map<String, Action> headers;
        public final Map<String, Action> cookies;
        public final Map<String, Action> path;
        public final List<BodyRule> body;

        Part(Map<String, Action> q, Map<String, Action> h, Map<String, Action> c, Map<String, Action> p, List<BodyRule> b) {
            this.query = q;
            this.headers = h;
            this.cookies = c;
            this.path = p;
            this.body = b;
        }
    }

    public record TemplateSeg(String lit, String param) {}

    public static final class Op {
        public final String key;
        public final String method;
        public final TemplateSeg[] segs;
        public final int literals;
        public final Part request;
        public final Part response;

        Op(String key, String method, TemplateSeg[] segs, int literals, Part request, Part response) {
            this.key = key;
            this.method = method;
            this.segs = segs;
            this.literals = literals;
            this.request = request;
            this.response = response;
        }
    }

    public static final class Base {
        public final String origin;
        public final List<String> segs;

        Base(String origin, List<String> segs) {
            this.origin = origin;
            this.segs = segs;
        }
    }

    public static final class Service {
        public final String name;
        public final boolean inbound;
        public final boolean internal;
        public final Base base;
        public final Part request;
        public final Part response;
        public final Part errors;
        public final List<Op> ops = new ArrayList<>();

        Service(String name, boolean inbound, boolean internal, Base base, Part request, Part response, Part errors) {
            this.name = name;
            this.inbound = inbound;
            this.internal = internal;
            this.base = base;
            this.request = request;
            this.response = response;
            this.errors = errors;
        }
    }

    public record Limits(int maxBodyBytes, int maxDepth, int maxArray, int maxKeys, int keepMaxBytes) {
        public static final Limits DEFAULT = new Limits(1048576, 32, 32, 256, 64);
    }

    /** {@code jsonPath} (spec v1.18): dotted path of members inside a header whose value is a JSON object, or base64 of one. */
    public record SubjectSpec(String from, String name, String jwtClaim, String jsonPath) {}

    /**
     * Spec v1.19 (sanitizer.md 22.1): body switches and large-body limits. {@link #OFF} when the
     * policy has no {@code bodies} object (behaviour before v1.19, byte for byte).
     */
    public record Bodies(boolean xml, boolean multipart, boolean docs, int maxLargeBodyBytes, int largeArray, int largeNestedArray) {
        public static final Bodies OFF = new Bodies(false, false, false, 0, 0, 0);
    }

    public final String policyId;
    public final long version;
    public final long issuedSeq;
    public final double createdAt;
    public final double notAfter;
    public final List<String> groups;
    public final String kid;
    public final List<String> acceptKids;
    public final String epoch;
    public final SubjectSpec subject;
    public final int rateBp;
    public final boolean trustBaggage;
    public final Set<String> propagateTo;
    public final boolean autoWords;
    public final double autoWordsExpiresAt;
    public final Set<String> allow;
    public final Set<String> hostsAllow;
    /** Spec v1.5: {@code hosts.discovery} is {@code auto} (default, also when absent) rather than {@code off}. */
    public final boolean hostsAuto;
    public final Limits limits;
    public final Bodies bodies;
    public final boolean discoveryEnabled;
    public final double discoveryExpiresAt;
    public final Part globalRequest;
    public final Part globalResponse;
    public final Part globalErrors;
    public final List<Service> services = new ArrayList<>();
    public final Map<String, Service> inbound = new HashMap<>();
    public final Set<String> baseHosts = new HashSet<>();
    /** SHA-256 of the body bytes, {@code sha256:<hex>}, when known. */
    public volatile String hash = "";

    @SuppressWarnings("unchecked")
    public Policy(Map<String, Object> b) {
        policyId = str(b.get("policy_id"), "");
        version = lng(b.get("version"), 0);
        issuedSeq = lng(b.get("issued_seq"), 0);
        createdAt = parseTime(b.get("created_at"));
        notAfter = parseTime(b.get("not_after"));
        Map<String, Object> targets = obj(b.get("targets"));
        groups = strList(targets == null ? null : targets.get("groups"));
        Map<String, Object> hmac = orEmpty(obj(b.get("hmac")));
        kid = str(hmac.get("kid"), "");
        acceptKids = strList(hmac.get("accept_kids"));
        epoch = str(hmac.get("epoch"), "");
        Map<String, Object> identity = obj(b.get("identity"));
        Map<String, Object> subj = identity == null ? null : obj(identity.get("subject"));
        if (subj != null) {
            subject = new SubjectSpec(str(subj.get("from"), "header"), str(subj.get("name"), ""),
                subj.get("jwt_claim") instanceof String s ? s : null, subj.get("json_path") instanceof String jp ? jp : null);
        } else subject = null;
        Map<String, Object> sampling = orEmpty(obj(b.get("sampling")));
        rateBp = (int) lng(sampling.get("rate_bp"), 0);
        trustBaggage = Boolean.TRUE.equals(sampling.get("trust_baggage"));
        propagateTo = new HashSet<>(strList(sampling.get("propagate_to")));
        Map<String, Object> seg = orEmpty(obj(b.get("segments")));
        autoWords = Boolean.TRUE.equals(seg.get("auto_words"));
        autoWordsExpiresAt = parseTime(seg.get("auto_words_expires_at"));
        allow = new HashSet<>(strList(seg.get("allow")));
        hostsAllow = new HashSet<>(strList(seg.get("hosts_allow")));
        hostsAuto = !"off".equals(orEmpty(obj(b.get("hosts"))).get("discovery"));
        Map<String, Object> lim = orEmpty(obj(b.get("limits")));
        Limits d = Limits.DEFAULT;
        limits = new Limits((int) lng(lim.get("max_body_bytes"), d.maxBodyBytes()), (int) lng(lim.get("max_depth"), d.maxDepth()),
            (int) lng(lim.get("max_array"), d.maxArray()), (int) lng(lim.get("max_keys"), d.maxKeys()),
            (int) lng(lim.get("keep_max_bytes"), d.keepMaxBytes()));
        Map<String, Object> bd = obj(b.get("bodies"));
        bodies = bd == null ? Bodies.OFF : new Bodies(Boolean.TRUE.equals(bd.get("xml")), Boolean.TRUE.equals(bd.get("multipart")),
            Boolean.TRUE.equals(bd.get("docs")), (int) lng(bd.get("max_large_body_bytes"), 0), (int) lng(bd.get("large_array"), 0),
            (int) lng(bd.get("large_nested_array"), 0));
        Map<String, Object> disc = obj(b.get("discovery"));
        discoveryEnabled = disc != null && Boolean.TRUE.equals(disc.get("enabled"));
        discoveryExpiresAt = parseTime(disc == null ? null : disc.get("expires_at"));
        Map<String, Object> g = orEmpty(obj(b.get("global")));
        globalRequest = part(g.get("request"));
        globalResponse = part(g.get("response"));
        globalErrors = part(g.get("errors"));
        Object svcs = b.get("services");
        if (svcs instanceof List<?> sl) {
            for (Object s : sl) {
                Map<String, Object> so = obj(s);
                if (so == null) continue;
                Map<String, Object> m = orEmpty(obj(so.get("match")));
                Base base = null;
                if (m.get("base") instanceof String bs) {
                    base = splitBase(bs);
                    String auth = base.origin.replaceFirst("^[a-z]+://", "");
                    baseHosts.add(auth);
                    baseHosts.add(auth.replaceFirst(":[0-9]+$", ""));
                }
                Service svc = new Service(str(so.get("name"), ""), Boolean.TRUE.equals(m.get("inbound")),
                    Boolean.TRUE.equals(m.get("internal")), base, part(so.get("request")), part(so.get("response")), part(so.get("errors")));
                if (so.get("ops") instanceof List<?> ol) {
                    for (Object o : ol) {
                        Map<String, Object> oo = obj(o);
                        if (oo == null) continue;
                        Op parsed = parseOpKey(str(oo.get("op"), ""), part(oo.get("request")), part(oo.get("response")));
                        if (parsed != null) svc.ops.add(parsed);
                    }
                }
                services.add(svc);
                if (svc.inbound && !inbound.containsKey(svc.name)) inbound.put(svc.name, svc);
            }
        }
    }

    /** 9.0 and 22.5: bytes of a body a source keeps (tee), {@code max(max_body_bytes, bodies.max_large_body_bytes) + 1}. */
    public int captureLimit() {
        return Math.max(limits.maxBodyBytes(), bodies.maxLargeBodyBytes()) + 1;
    }

    /** 4.3: auto words active at {@code now} (ms). */
    public boolean autoWordsActive(double now) {
        return autoWords && now < autoWordsExpiresAt && now < createdAt + 7 * DAY_MS;
    }

    /** 15: discovery active at {@code now} (ms). */
    public boolean discoveryActive(double now) {
        return discoveryEnabled && now < discoveryExpiresAt && now < createdAt + 7 * DAY_MS;
    }

    // ---------------------------------------------------------------------------------
    // Plain-document accessors

    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Object v) {
        return v instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
    }

    static Map<String, Object> orEmpty(Map<String, Object> m) {
        return m == null ? Map.of() : m;
    }

    static String str(Object v, String d) {
        return v instanceof String s ? s : d;
    }

    static long lng(Object v, long d) {
        if (v instanceof Lex l) {
            try {
                return (long) Double.parseDouble(l.lex);
            } catch (NumberFormatException e) {
                return d;
            }
        }
        return d;
    }

    static List<String> strList(Object v) {
        List<String> out = new ArrayList<>();
        if (v instanceof List<?> l) for (Object x : l) out.add(str(x, ""));
        return out;
    }

    private static final Pattern RFC3339 = Pattern.compile(
        "([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\\.[0-9]+)?([Zz]|([+-])([0-9]{2}):([0-9]{2}))");

    /** RFC 3339 timestamp to epoch milliseconds; NaN when absent or malformed. */
    public static double parseTime(Object v) {
        if (!(v instanceof String s)) return Double.NaN;
        Matcher m = RFC3339.matcher(s);
        if (!m.matches()) return Double.NaN;
        try {
            int y = Integer.parseInt(m.group(1));
            int mo = Integer.parseInt(m.group(2));
            int d = Integer.parseInt(m.group(3));
            int h = Integer.parseInt(m.group(4));
            int mi = Integer.parseInt(m.group(5));
            int se = Integer.parseInt(m.group(6));
            if (h > 23 || mi > 59 || se > 60) return Double.NaN;
            LocalDateTime t = LocalDateTime.of(y, mo, d, h, mi, 0);
            double ms = t.toEpochSecond(ZoneOffset.UTC) * 1000d + se * 1000d;
            if (m.group(7) != null) ms += Math.floor(Double.parseDouble("0" + m.group(7)) * 1000);
            if (m.group(9) != null) {
                double off = (Integer.parseInt(m.group(10)) * 60 + Integer.parseInt(m.group(11))) * 60_000d;
                ms += "+".equals(m.group(9)) ? -off : off;
            }
            return ms;
        } catch (DateTimeException | NumberFormatException e) {
            return Double.NaN;
        }
    }

    private static Action parseAction(Object v) {
        Map<String, Object> o = obj(v);
        if (o == null) return null;
        Object a = o.get("action");
        if ("drop".equals(a)) return Action.DROP;
        if ("keep".equals(a)) return Action.KEEP;
        if ("code".equals(a)) return "alnum".equals(o.get("shape")) ? Action.CODE_ALNUM : Action.CODE;
        if ("graphql".equals(a)) return Action.GRAPHQL;
        if ("hmac".equals(a)) return new Action("hmac", str(o.get("domain"), "id"), null, null, null);
        if ("bucket".equals(a) && "num".equals(o.get("kind"))) {
            List<Bound> bounds = new ArrayList<>();
            if (o.get("bounds") instanceof List<?> l) {
                for (Object x : l) {
                    String lex = x instanceof Lex lx ? lx.lex : String.valueOf(x);
                    bounds.add(new Bound(Json.canonicalNumber(lex), Double.parseDouble(lex)));
                }
            }
            return new Action("bucket", null, "num", bounds, null);
        }
        if ("bucket".equals(a) && "time".equals(o.get("kind"))) return new Action("bucket", null, "time", null, str(o.get("unit"), "day"));
        return Action.DROP;
    }

    private static Map<String, Action> nameMap(Object v) {
        Map<String, Action> m = new LinkedHashMap<>();
        Map<String, Object> o = obj(v);
        if (o == null) return m;
        for (Map.Entry<String, Object> e : o.entrySet()) {
            Action a = parseAction(e.getValue());
            if (a != null) m.put(e.getKey(), a);
        }
        return m;
    }

    private static final Pattern NAME_STEP = Pattern.compile("[A-Za-z_][A-Za-z0-9_-]{0,63}");

    /**
     * Parses a tt-path; returns null if it does not follow the grammar. The v1.19 steps
     * {@code .@name} and {@code .#text} are member names "@name" and "#text".
     */
    public static Step[] parseTtPath(String p) {
        if (p.isEmpty() || p.charAt(0) != '$') return null;
        List<Step> steps = new ArrayList<>();
        int i = 1;
        while (i < p.length()) {
            if (p.startsWith(".#text", i)) {
                steps.add(new Step(Step.NAME, "#text"));
                i += 6;
            } else if (p.startsWith(".@", i)) {
                int j = i + 2;
                while (j < p.length() && j - (i + 2) < 64) {
                    char c = p.charAt(j);
                    boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || (j > i + 2 && ((c >= '0' && c <= '9') || c == '-'));
                    if (!ok) break;
                    j++;
                }
                String name = p.substring(i + 2, j);
                if (!NAME_STEP.matcher(name).matches()) return null;
                steps.add(new Step(Step.NAME, "@" + name));
                i = j;
            } else if (p.startsWith(".*", i)) {
                steps.add(new Step(Step.ANY, null));
                i += 2;
            } else if (p.startsWith("[*]", i)) {
                steps.add(new Step(Step.IDX, null));
                i += 3;
            } else if (p.charAt(i) == '.') {
                int j = i + 1;
                while (j < p.length() && j - (i + 1) < 64) {
                    char c = p.charAt(j);
                    boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || (j > i + 1 && ((c >= '0' && c <= '9') || c == '-'));
                    if (!ok) break;
                    j++;
                }
                String name = p.substring(i + 1, j);
                if (!NAME_STEP.matcher(name).matches()) return null;
                steps.add(new Step(Step.NAME, name));
                i = j;
            } else return null;
        }
        return steps.toArray(new Step[0]);
    }

    private static Part part(Object v) {
        Map<String, Object> o = obj(v);
        if (o == null) return null;
        List<BodyRule> body = new ArrayList<>();
        if (o.get("body") instanceof List<?> l) {
            for (Object r : l) {
                Map<String, Object> ro = obj(r);
                if (ro == null) continue;
                String path = str(ro.get("path"), "");
                Step[] steps = parseTtPath(path);
                Action action = parseAction(ro.get("action"));
                if (steps == null || action == null) continue;
                body.add(new BodyRule(path, steps, action));
            }
        }
        return new Part(nameMap(o.get("query")), nameMap(o.get("headers")), nameMap(o.get("cookies")), nameMap(o.get("path")), body);
    }

    static Op parseOpKey(String key, Part request, Part response) {
        int sp = key.indexOf(' ');
        if (sp <= 0) return null;
        String method = key.substring(0, sp);
        String tmpl = key.substring(sp + 1);
        if (tmpl.isEmpty() || tmpl.charAt(0) != '/') return null;
        List<TemplateSeg> segs = new ArrayList<>();
        int literals = 0;
        for (String s : tmpl.split("/", -1)) {
            if (s.isEmpty()) continue;
            if (s.charAt(0) == '{' && s.charAt(s.length() - 1) == '}') segs.add(new TemplateSeg(null, s.substring(1, s.length() - 1)));
            else {
                segs.add(new TemplateSeg(s, null));
                literals++;
            }
        }
        return new Op(key, method, segs.toArray(new TemplateSeg[0]), literals, request, response);
    }

    private static final Pattern BASE = Pattern.compile("([a-z][a-z0-9+.-]*://[^/]*)(/.*)?", Pattern.DOTALL);

    /** Splits a normalized {@code match.base} into origin and path segments. */
    static Base splitBase(String base) {
        Matcher m = BASE.matcher(base);
        if (!m.matches()) return new Base(base, List.of());
        List<String> segs = new ArrayList<>();
        if (m.group(2) != null) for (String s : m.group(2).split("/", -1)) if (!s.isEmpty()) segs.add(s);
        return new Base(m.group(1), segs);
    }
}
