package io.github.ivseb.traffictwin.sanitizer;

import io.github.ivseb.traffictwin.sanitizer.Exchange.Header;
import io.github.ivseb.traffictwin.sanitizer.Json.Arr;
import io.github.ivseb.traffictwin.sanitizer.Json.CNum;
import io.github.ivseb.traffictwin.sanitizer.Json.Node;
import io.github.ivseb.traffictwin.sanitizer.Json.Obj;
import io.github.ivseb.traffictwin.sanitizer.Json.Str;
import io.github.ivseb.traffictwin.sanitizer.KeyRing.KeyRef;
import io.github.ivseb.traffictwin.sanitizer.Policy.Action;
import io.github.ivseb.traffictwin.sanitizer.Policy.BodyRule;
import io.github.ivseb.traffictwin.sanitizer.Policy.Op;
import io.github.ivseb.traffictwin.sanitizer.Policy.Part;
import io.github.ivseb.traffictwin.sanitizer.Policy.Service;
import io.github.ivseb.traffictwin.sanitizer.Policy.Step;
import io.github.ivseb.traffictwin.sanitizer.Policy.TemplateSeg;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.YearMonth;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.DoubleSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The sanitizer, docs/spec/sanitizer.md (v1.19: XML and SOAP, multipart, base64 documents, large
 * bodies, code(alnum)). Input: one normalized exchange (section 1), a
 * verified compiled policy, the local HMAC key and the clock. Output: the canonical object of
 * section 2, or "not sampled".
 *
 * <p>Guiding rule: in doubt, drop. Any exception escaping from {@link #run} must be treated by
 * the caller as an internal error (no event, {@code sanitizer_errors} + 1). Instances are
 * immutable and thread safe.
 */
public final class Sanitizer {
    public static final int MAX_EVENT_BYTES = 524288;
    private static final int MAX_SEGMENTS = 32;
    private static final int MAX_NAMES = 64;
    private static final int MAX_DISC = 4096;
    private static final int SUBJECT_MAX = 8192;
    private static final byte[] SEP_COMMA = {',', ' '};
    private static final byte[] SEP_SEMI = {';', ' '};

    /** Sampling decision. */
    public record Decision(boolean sampled, String by) {}

    /** Outcome of {@link #run}. */
    public static final class Result {
        /** event | not_sampled | too_large */
        public final String outcome;
        public final String sampledBy;
        /** Sanitizer output members, serialized one by one (event assembly reuses them). */
        public final Map<String, String> parts;
        public final String canonical;

        Result(String outcome, String sampledBy, Map<String, String> parts, String canonical) {
            this.outcome = outcome;
            this.sampledBy = sampledBy;
            this.parts = parts;
            this.canonical = canonical;
        }
    }

    public final Policy policy;
    public final KeyRef key;
    private final Integer rateOverrideBp;
    private final DoubleSupplier rand;
    private final byte[] epochBytes;
    private final SecretKeySpec keySpec;
    private final ThreadLocal<Mac> mac;

    public Sanitizer(Policy policy, KeyRef key) {
        this(policy, key, null, null);
    }

    public Sanitizer(Policy policy, KeyRef key, Integer rateOverrideBp, DoubleSupplier rand) {
        this.policy = policy;
        this.key = key;
        this.rateOverrideBp = rateOverrideBp;
        this.rand = rand != null ? rand : () -> ThreadLocalRandom.current().nextDouble();
        this.epochBytes = policy.epoch.getBytes(StandardCharsets.ISO_8859_1);
        this.keySpec = new SecretKeySpec(key.key(), "HmacSHA256");
        this.mac = ThreadLocal.withInitial(() -> {
            try {
                Mac m = Mac.getInstance("HmacSHA256");
                m.init(keySpec);
                return m;
            } catch (java.security.GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        });
    }

    public Integer rateOverrideBp() {
        return rateOverrideBp;
    }

    byte[] mac(String domain, byte[] value) {
        Mac m = mac.get();
        m.reset();
        m.update(epochBytes);
        m.update((byte) 0);
        m.update(domain.getBytes(StandardCharsets.ISO_8859_1));
        m.update((byte) 0);
        m.update(value);
        return m.doFinal();
    }

    String token(String domain, byte[] value) {
        return "tk1:" + key.kid() + ":" + Base64Url.encode(mac(domain, value), 16);
    }

    int rateBp() {
        return rateOverrideBp != null ? Math.min(rateOverrideBp, policy.rateBp) : policy.rateBp;
    }

    // ---------------------------------------------------------------------------------
    // Header normalization (8.0)

    static final class HdrEntry {
        final String out;
        final List<byte[]> values = new ArrayList<>();
        final Set<String> origs = new LinkedHashSet<>();

        HdrEntry(String out) {
            this.out = out;
        }
    }

    static final class Headers {
        final List<String> order = new ArrayList<>();
        final Map<String, HdrEntry> map = new HashMap<>();
    }

    static Headers normalizeHeaders(List<Header> list) {
        Headers h = new Headers();
        if (list == null) return h;
        for (Header hd : list) {
            String name = hd.name();
            if (!name.isEmpty() && name.charAt(0) == ':') continue;
            String lower = Utf8.asciiLower(name);
            String out = Formats.headerOutName(lower);
            HdrEntry e = h.map.get(out);
            if (e == null) {
                e = new HdrEntry(out);
                h.map.put(out, e);
                h.order.add(out);
            }
            e.values.add(Utf8.trimOws(hd.value()));
            e.origs.add(lower);
        }
        return h;
    }

    static byte[] joinValues(List<byte[]> values, boolean cookie) {
        if (values.size() == 1) return values.get(0);
        List<byte[]> parts = new ArrayList<>();
        byte[] sep = cookie ? SEP_SEMI : SEP_COMMA;
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) parts.add(sep);
            parts.add(values.get(i));
        }
        return Utf8.concat(parts);
    }

    private static byte[] joined(HdrEntry e) {
        return joinValues(e.values, e.out.equals("cookie"));
    }

    /** Joined value of one exact lowercase header name (subject, baggage); null if absent. */
    static byte[] headerValue(List<Header> list, String lower) {
        List<byte[]> vals = new ArrayList<>();
        if (list != null) {
            for (Header h : list) {
                String n = h.name();
                if (!n.isEmpty() && n.charAt(0) == ':') continue;
                if (Utf8.asciiLower(n).equals(lower)) vals.add(Utf8.trimOws(h.value()));
            }
        }
        if (vals.isEmpty()) return null;
        return joinValues(vals, lower.equals("cookie"));
    }

    private static final Pattern CT = Pattern.compile("[a-z0-9.+-]{1,64}/[a-z0-9.+-]{1,64}");

    /** 8.1.5: {@code ct} from the normalized content-type value; null without the header. */
    static String contentType(Headers h) {
        HdrEntry e = h.map.get("content-type");
        if (e == null) return null;
        byte[] v = joined(e);
        int semi = Utf8.indexOf(v, ';');
        if (semi >= 0) v = java.util.Arrays.copyOf(v, semi);
        String s = Utf8.asciiLower(new String(Utf8.trimOws(v), StandardCharsets.ISO_8859_1));
        return CT.matcher(s).matches() ? s : "invalid";
    }

    private static String contentEncoding(Headers h) {
        HdrEntry e = h.map.get("content-encoding");
        if (e == null) return null;
        return Utf8.asciiLower(new String(Utf8.trimOws(joined(e)), StandardCharsets.ISO_8859_1));
    }

    // ---------------------------------------------------------------------------------
    // Path (4.1) and routing (3)

    record Seg(String dec) {}

    record Decomposed(List<Seg> segs, boolean truncated) {}

    static Decomposed decomposePath(byte[] raw) {
        List<Seg> segs = new ArrayList<>();
        boolean truncated = false;
        for (byte[] s : Utf8.split(raw, '/')) {
            if (s.length == 0) continue;
            if (segs.size() == MAX_SEGMENTS) {
                truncated = true;
                break;
            }
            segs.add(new Seg(Utf8.decode(Utf8.pctDecode(s, false))));
        }
        return new Decomposed(segs, truncated);
    }

    /** Normalized {@code url_base}; {@code host}/{@code port} (port "" when absent or default) and {@code ip6} (16 bytes of a bracketed literal, else null) feed 3.5. */
    record UrlBase(boolean invalid, String origin, String hostport, String host, String port, byte[] ip6) {
        static final UrlBase BAD = new UrlBase(true, "", "", "", "", null);
    }

    private static final Pattern URL_BASE = Pattern.compile("([A-Za-z][A-Za-z0-9+.-]*)://(.*)", Pattern.DOTALL);
    private static final Pattern HOST = Pattern.compile("[a-z0-9.-]{1,253}");
    private static final Pattern PORT = Pattern.compile("[0-9]{1,5}");

    /** 3.1 normalization of {@code url_base} (with the IPv6 literals of spec v1.5). */
    static UrlBase normalizeUrlBase(String u) {
        UrlBase bad = UrlBase.BAD;
        if (u == null) return bad;
        Matcher m = URL_BASE.matcher(u);
        if (!m.matches()) return bad;
        String scheme = Utf8.asciiLower(m.group(1));
        String rest = m.group(2);
        for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            if (c == '@' || c == '/' || c == '?' || c == '#') return bad;
        }
        String host;
        String portText = null;
        byte[] ip6 = null;
        if (rest.startsWith("[")) {
            int end = rest.indexOf(']');
            if (end < 0) return bad;
            String inner = Utf8.asciiLower(rest.substring(1, end));
            String after = rest.substring(end + 1);
            ip6 = HostPattern.parseIpv6(inner);
            if (ip6 == null) return bad;
            if (after.startsWith(":")) portText = after.substring(1);
            else if (!after.isEmpty()) return bad;
            host = "[" + inner + "]";
        } else {
            host = rest;
            int c = rest.lastIndexOf(':');
            if (c >= 0) {
                host = rest.substring(0, c);
                portText = rest.substring(c + 1);
            }
            host = Utf8.asciiLower(host);
            if (!HOST.matcher(host).matches()) return bad;
        }
        String port = "";
        if (portText != null) {
            if (!PORT.matcher(portText).matches()) return bad;
            int pn = Integer.parseInt(portText);
            if (pn < 1 || pn > 65535) return bad;
            port = String.valueOf(pn);
            if ((scheme.equals("http") && pn == 80) || (scheme.equals("https") && pn == 443)) port = "";
        }
        String hostport = port.isEmpty() ? host : host + ":" + port;
        return new UrlBase(false, scheme + "://" + hostport, hostport, host, port, ip6);
    }

    public static final Set<String> FRAMEWORKS = Set.of(
        "express", "koa", "fastify", "flask", "fastapi", "django", "spring", "jaxrs",
        "aspnetcore", "gin", "chi", "nethttp", "laravel", "symfony");

    private static final String PN = "[A-Za-z_][A-Za-z0-9_]{0,63}";
    private static final Pattern RE_COLON = Pattern.compile(":(" + PN + ")");
    private static final Pattern RE_COLON_REGEX = Pattern.compile(":(" + PN + ")\\((.*)\\)", Pattern.DOTALL);
    private static final Pattern RE_ANGLE = Pattern.compile("<(?:([A-Za-z_][A-Za-z0-9_]*):)?(" + PN + ")>");
    private static final Pattern RE_BRACE = Pattern.compile("\\{(" + PN + ")\\}");
    private static final Pattern RE_BRACE_CONV = Pattern.compile("\\{(" + PN + "):(.+)\\}", Pattern.DOTALL);
    private static final Pattern RE_BRACE_SYMFONY = Pattern.compile("\\{(" + PN + ")<(.+)>\\}", Pattern.DOTALL);
    private static final Pattern RE_PNAME = Pattern.compile(PN);
    private static final Pattern RE_COLON_PARAM = Pattern.compile(":[A-Za-z_]");

    /** One segment of a framework route: the parameter name, or null when it is not a parameter syntax of that framework. */
    static String frameworkParam(String fw, String s) {
        Matcher m;
        switch (fw) {
            case "express":
            case "koa":
            case "fastify":
                if ((m = RE_COLON.matcher(s)).matches()) return m.group(1);
                // ":name(regex)"; a regex holding another ":param" means several parameters.
                if ((m = RE_COLON_REGEX.matcher(s)).matches() && !RE_COLON_PARAM.matcher(m.group(2).replaceAll("\\\\.", "")).find()) return m.group(1);
                return null;
            case "gin":
                return (m = RE_COLON.matcher(s)).matches() ? m.group(1) : null;
            case "flask":
            case "django":
                return (m = RE_ANGLE.matcher(s)).matches() && !"path".equals(m.group(1)) ? m.group(2) : null;
            case "fastapi":
                if ((m = RE_BRACE.matcher(s)).matches()) return m.group(1);
                return (m = RE_BRACE_CONV.matcher(s)).matches() && !m.group(2).equals("path") ? m.group(1) : null;
            case "spring":
            case "chi":
                if ((m = RE_BRACE.matcher(s)).matches()) return m.group(1);
                return (m = RE_BRACE_CONV.matcher(s)).matches() ? m.group(1) : null;
            case "jaxrs": {
                // "{ name : regex }": spaces around the name and the colon are ignored.
                if (s.length() < 2 || s.charAt(0) != '{' || s.charAt(s.length() - 1) != '}') return null;
                String inner = s.substring(1, s.length() - 1);
                int c = inner.indexOf(':');
                String name = (c < 0 ? inner : inner.substring(0, c)).strip();
                if (!RE_PNAME.matcher(name).matches()) return null;
                if (c >= 0 && inner.substring(c + 1).strip().isEmpty()) return null;
                return name;
            }
            case "aspnetcore":
                if ((m = RE_BRACE.matcher(s)).matches()) return m.group(1);
                // "{name:constraint[:constraint...]}"; "?" marks an optional parameter, "=" a default.
                if ((m = RE_BRACE_CONV.matcher(s)).matches() && !m.group(2).endsWith("?") && !m.group(2).contains("=")) return m.group(1);
                return null;
            case "nethttp":
            case "laravel":
                return (m = RE_BRACE.matcher(s)).matches() ? m.group(1) : null;
            case "symfony":
                if ((m = RE_BRACE.matcher(s)).matches()) return m.group(1);
                return (m = RE_BRACE_SYMFONY.matcher(s)).matches() ? m.group(1) : null;
            default:
                return null;
        }
    }

    /**
     * 3.4 with A-FRAMEWORK-ID (normative since 1.1.1): normalizes {@code route} with the table of
     * {@code framework}. Every segment must be a parameter syntax of that framework or a literal
     * of the operation-key grammar; anything else (every "not normalizable" case) fails.
     */
    public static TemplateSeg[] normalizeFrameworkRoute(String route, String framework) {
        if (!FRAMEWORKS.contains(framework)) return null;
        List<String> raw = new ArrayList<>();
        for (String s : route.split("/", -1)) if (!s.isEmpty()) raw.add(s);
        List<TemplateSeg> out = new ArrayList<>();
        for (int i = 0; i < raw.size(); i++) {
            String s = raw.get(i);
            if (framework.equals("nethttp") && s.equals("{$}") && i == raw.size() - 1) continue; // exact-match marker
            String p = frameworkParam(framework, s);
            if (p != null) out.add(new TemplateSeg(null, p));
            else if (Formats.PATH_TOKEN.matcher(s).matches()) out.add(new TemplateSeg(s, null));
            else return null;
        }
        return out.size() > MAX_SEGMENTS ? null : out.toArray(new TemplateSeg[0]);
    }

    // ---------------------------------------------------------------------------------
    // Buckets (5.5)

    private static final Pattern TIME_PARSE = Pattern.compile(
        "([0-9]{4})-([0-9]{2})-([0-9]{2})(?:[Tt ]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\\.[0-9]{1,9})?(?:[Zz]|([+-])([0-9]{2}):([0-9]{2})))?");

    static String bucketTime(String s, String unit) {
        if (!Formats.isPrintableAscii(s) || !(Formats.DATETIME.matcher(s).matches() || Formats.DATE.matcher(s).matches())) return null;
        Matcher m = TIME_PARSE.matcher(s);
        if (!m.matches()) return null;
        int y = Integer.parseInt(m.group(1));
        int mo = Integer.parseInt(m.group(2));
        int d = Integer.parseInt(m.group(3));
        int h = m.group(4) != null ? Integer.parseInt(m.group(4)) : 0;
        int mi = m.group(5) != null ? Integer.parseInt(m.group(5)) : 0;
        int se = m.group(6) != null ? Integer.parseInt(m.group(6)) : 0;
        if (y < 1 || y > 9999 || mo < 1 || mo > 12 || d < 1) return null;
        if (d > YearMonth.of(y, mo).lengthOfMonth() || h > 23 || mi > 59 || se > 59) return null;
        int off = 0;
        if (m.group(7) != null) {
            int oh = Integer.parseInt(m.group(8));
            int om = Integer.parseInt(m.group(9));
            if (oh > 23 || om > 59) return null;
            off = (oh * 60 + om) * (m.group(7).equals("+") ? 1 : -1);
        }
        LocalDateTime t = LocalDateTime.of(y, mo, d, h, mi).minusMinutes(off);
        int uy = t.getYear();
        if (uy < 1 || uy > 9999) return null;
        String ys = String.format("%04d", uy);
        String ms = String.format("%02d", t.getMonthValue());
        String ds = String.format("%02d", t.getDayOfMonth());
        switch (unit) {
            case "year": return "time:" + ys;
            case "month": return "time:" + ys + "-" + ms;
            case "day": return "time:" + ys + "-" + ms + "-" + ds;
            case "hour": return "time:" + ys + "-" + ms + "-" + ds + "T" + String.format("%02d", t.getHour());
            default: return null;
        }
    }

    static String bucketNum(String lex, Action a) {
        List<Policy.Bound> b = a.bounds;
        double v = Double.parseDouble(lex);
        if (v < b.get(0).d()) return "num:<" + b.get(0).canon();
        for (int i = 0; i + 1 < b.size(); i++) {
            if (v >= b.get(i).d() && v < b.get(i + 1).d()) return "num:" + b.get(i).canon() + "-" + b.get(i + 1).canon();
        }
        return "num:>=" + b.get(b.size() - 1).canon();
    }

    // ---------------------------------------------------------------------------------
    // Subject (11)

    private static final Pattern BEARER = Pattern.compile("bearer[ \\t]+", Pattern.CASE_INSENSITIVE);

    byte[] subjectValue(List<Header> reqHeaders) {
        Policy.SubjectSpec spec = policy.subject;
        if (spec == null) return null;
        byte[] raw = null;
        if (spec.from().equals("header")) {
            raw = headerValue(reqHeaders, Utf8.asciiLower(spec.name()));
        } else {
            byte[] cookie = headerValue(reqHeaders, "cookie");
            if (cookie != null) {
                for (byte[] p : Utf8.split(cookie, ';')) {
                    byte[] piece = Utf8.trimOws(p);
                    int eq = Utf8.indexOf(piece, '=');
                    if (eq < 0) continue;
                    if (spec.name().equals(Utf8.decode(piece, 0, eq))) {
                        raw = java.util.Arrays.copyOfRange(piece, eq + 1, piece.length);
                        break;
                    }
                }
            }
        }
        if (raw == null || raw.length == 0 || raw.length > SUBJECT_MAX) return null;
        String s = Utf8.decode(raw);
        if (s == null || s.isEmpty()) return null;
        if (spec.from().equals("header") && spec.jsonPath() != null) return jsonMember(s, spec.jsonPath());
        if (spec.from().equals("header")) {
            Matcher m = BEARER.matcher(s);
            if (m.lookingAt()) {
                s = s.substring(m.end());
                if (s.isEmpty()) return null;
            }
        }
        if (spec.jwtClaim() == null) return Utf8.encode(s);
        String[] parts = s.split("\\.", -1);
        if (parts.length != 3) return null;
        String payload = parts[1].replaceFirst("={1,2}$", "");
        byte[] bytes = Base64Url.decodeStrict(payload);
        if (bytes == null) return null;
        Node doc;
        try {
            doc = Json.parse(bytes);
        } catch (Json.JsonError e) {
            return null;
        }
        if (!(doc instanceof Obj o)) return null;
        Node v = null;
        for (int i = 0; i < o.size(); i++) {
            Str k = o.keys.get(i);
            if (!k.bad && k.s.equals(spec.jwtClaim())) v = o.values.get(i);
        }
        if (v == null) return null;
        if (v instanceof Str st) return !st.s.isEmpty() && !st.bad ? Utf8.encode(st.s) : null;
        if (v instanceof Json.Num n) {
            return Json.lexemeWithinLimits(n.lex) ? Json.canonicalNumber(n.lex).getBytes(StandardCharsets.ISO_8859_1) : null;
        }
        return null;
    }

    /**
     * Standard or URL-safe base64 (never mixed), with or without padding (at most two '=' at the end, then a length
     * that is a multiple of 4). Null on any other character or an impossible length.
     */
    private static byte[] b64Any(String s) {
        int end = s.length();
        for (int k = 0; k < 2 && end > 0 && s.charAt(end - 1) == '='; k++) end--;
        if (end == 0 || (end != s.length() && s.length() % 4 != 0) || end % 4 == 1) return null;
        boolean std = false;
        boolean url = false;
        for (int i = 0; i < end; i++) {
            char c = s.charAt(i);
            if (c == '+' || c == '/') std = true;
            else if (c == '-' || c == '_') url = true;
            else if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) return null;
        }
        if (std && url) return null;
        try {
            return (std ? java.util.Base64.getDecoder() : java.util.Base64.getUrlDecoder()).decode(s.substring(0, end));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Spec v1.18 (sanitizer.md 11, step 4 bis): the subject is a member of a header whose value is a JSON object, or
     * base64/base64url of one. No bearer prefix is stripped; the dot always separates members.
     */
    private static byte[] jsonMember(String s, String path) {
        int a = 0;
        int b = s.length();
        while (a < b && (s.charAt(a) == ' ' || s.charAt(a) == '\t')) a++;
        while (b > a && (s.charAt(b - 1) == ' ' || s.charAt(b - 1) == '\t')) b--;
        String t = s.substring(a, b);
        if (t.isEmpty()) return null;
        byte[] bytes = t.charAt(0) == '{' ? Utf8.encode(t) : b64Any(t);
        if (bytes == null) return null;
        Node v;
        try {
            v = Json.parse(bytes);
        } catch (Json.JsonError e) {
            return null;
        }
        for (String name : path.split("\\.", -1)) {
            if (!(v instanceof Obj o)) return null;
            Node found = null;
            for (int i = 0; i < o.size(); i++) {
                Str k = o.keys.get(i);
                if (!k.bad && k.s.equals(name)) found = o.values.get(i);
            }
            if (found == null) return null;
            v = found;
        }
        if (v instanceof Str st) return !st.s.isEmpty() && !st.bad ? Utf8.encode(st.s) : null;
        if (v instanceof Json.Num n) {
            return Json.lexemeWithinLimits(n.lex) ? Json.canonicalNumber(n.lex).getBytes(StandardCharsets.ISO_8859_1) : null;
        }
        return null;
    }

    // ---------------------------------------------------------------------------------
    // Sampling (12)

    private boolean hashSample(String domain, byte[] value) {
        byte[] m = mac(domain, value);
        long u = ((m[0] & 0xffL) << 24) | ((m[1] & 0xffL) << 16) | ((m[2] & 0xffL) << 8) | (m[3] & 0xffL);
        return u % 10000 < rateBp();
    }

    private boolean randomSample() {
        int rate = rateBp();
        if (rate <= 0) return false;
        if (rate >= 10000) return true;
        return (int) Math.floor(rand.getAsDouble() * 10000) < rate;
    }

    /** Sampling decision for an exchange (needs only the request line and headers). */
    public Decision decide(Exchange ex) {
        return decide(ex, null, false);
    }

    private Decision decide(Exchange ex, byte[] subject, boolean haveSubject) {
        if (ex.inbound) {
            Service svc = ex.serviceName != null ? policy.inbound.get(ex.serviceName) : null;
            if (policy.trustBaggage && svc != null && svc.internal) {
                byte[] bag = headerValue(ex.reqHeaders, "baggage");
                String s = bag != null ? Utf8.decode(bag) : null;
                if (s != null) {
                    for (String member : s.split(",", -1)) {
                        int sc = member.indexOf(';');
                        String kv = Utf8.trimOws(sc >= 0 ? member.substring(0, sc) : member);
                        int eq = kv.indexOf('=');
                        if (eq < 0) continue;
                        String k = Utf8.trimOws(kv.substring(0, eq));
                        String v = Utf8.trimOws(kv.substring(eq + 1));
                        if (k.equals("tt.s") && (v.equals("0") || v.equals("1"))) return new Decision(v.equals("1"), "baggage");
                    }
                }
            }
            byte[] subj = haveSubject ? subject : subjectValue(ex.reqHeaders);
            if (subj != null && subj.length > 0) return new Decision(hashSample("sample", subj), "subject");
        } else if (ex.inherited != null) {
            return new Decision(ex.inherited, "inherited");
        }
        if (ex.traceId != null && !ex.traceId.isEmpty()) {
            return new Decision(hashSample("sample-trace", Utf8.asciiLower(ex.traceId).getBytes(StandardCharsets.ISO_8859_1)), "trace");
        }
        return new Decision(randomSample(), "random");
    }

    // ---------------------------------------------------------------------------------
    // Whole exchange

    /** Sanitizes one exchange. {@code nowMs} is the source clock (epoch ms); {@code decision} may be precomputed. */
    public Result run(Exchange ex, double nowMs, Decision decision) {
        byte[] subject = subjectValue(ex.reqHeaders);
        Decision d = decision != null ? decision : decide(ex, subject, true);
        if (!d.sampled()) return new Result("not_sampled", d.by(), null, null);
        Run run = new Run(this, ex, nowMs);
        Map<String, Object> out = run.build(d.by(), subject);
        // Each top-level member is serialized once; the source reuses these parts to assemble
        // the full event without serializing the tree again.
        Map<String, String> parts = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : out.entrySet()) parts.put(e.getKey(), Json.writeCanonical(e.getValue()));
        String canonical = composeCanonical(parts);
        // 10.3, measured on the sanitizer output (A-EVENT-SIZE-BASE). Canonical output is ASCII.
        if (canonical.length() > MAX_EVENT_BYTES) {
            String[] steps = {"req", "resp", "disc"};
            for (String step : steps) {
                boolean changed;
                if (step.equals("disc")) changed = out.remove("disc") != null;
                else changed = replaceBody(out.get(step));
                if (!changed) continue;
                if (out.containsKey(step)) parts.put(step, Json.writeCanonical(out.get(step)));
                else parts.remove(step);
                canonical = composeCanonical(parts);
                if (canonical.length() <= MAX_EVENT_BYTES) break;
            }
            if (canonical.length() > MAX_EVENT_BYTES) return new Result("too_large", d.by(), null, null);
        }
        return new Result("event", d.by(), parts, canonical);
    }

    /** tt-cjson object from already serialized members (keys sorted by bytes). */
    public static String composeCanonical(Map<String, String> parts) {
        List<String> keys = new ArrayList<>(parts.keySet());
        keys.sort(Utf8::cmp);
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < keys.size(); i++) {
            if (i > 0) sb.append(',');
            Json.writeString(sb, keys.get(i));
            sb.append(':').append(parts.get(keys.get(i)));
        }
        return sb.append('}').toString();
    }

    @SuppressWarnings("unchecked")
    private static boolean replaceBody(Object side) {
        if (!(side instanceof Map<?, ?> m) || !m.containsKey("body")) return false;
        ((Map<String, Object>) side).put("body", "trunc:size");
        return true;
    }

    // ---------------------------------------------------------------------------------
    // Per-exchange state

    private static final class NamedEntry {
        final String orig;
        final String out;
        final byte[] value;
        final boolean noEq;
        /** A ready token (multipart file part, 22.3): no rule and no discovery. */
        final String token;

        NamedEntry(String orig, String out, byte[] value, boolean noEq) {
            this(orig, out, value, noEq, null);
        }

        NamedEntry(String orig, String out, byte[] value, boolean noEq, String token) {
            this.orig = orig;
            this.out = out;
            this.value = value;
            this.noEq = noEq;
            this.token = token;
        }
    }

    private static final class Run {
        final Sanitizer s;
        final Policy p;
        final Exchange ex;
        final Map<String, byte[]> disc;
        final boolean autoWords;
        Service svc;
        Op op;
        /** Walk of the current body: XML key rule (22.2 point 8) and large-body array caps (22.5). */
        boolean walkXml;
        boolean walkLarge;
        /** Array limit in force (9.4); raised for a response body with the introspection gate open (5.7.2). */
        int maxArray;
        // GraphQL (5.7, spec v1.14): resp is set while the response is sanitized; gqlSeen and
        // gqlNonIntro record the request values with a graphql rule (introspection gate).
        boolean resp;
        boolean gqlSeen;
        boolean gqlNonIntro;

        Run(Sanitizer s, Exchange ex, double now) {
            this.s = s;
            this.p = s.policy;
            this.ex = ex;
            this.disc = p.discoveryActive(now) ? new HashMap<>() : null;
            this.autoWords = p.autoWordsActive(now);
            this.maxArray = p.limits.maxArray();
        }

        Map<String, Object> build(String by, byte[] subject) {
            String method = Utf8.asciiUpper(ex.method == null ? "" : ex.method);
            if (!Pattern.matches("[A-Z]{1,16}", method)) method = "OTHER";
            Decomposed dp = decomposePath(ex.rawPath == null ? new byte[0] : ex.rawPath);
            List<Seg> segs = dp.segs();
            boolean truncated = dp.truncated();

            // 3.1 service
            String service;
            int baseCount = 0;
            if (ex.inbound) {
                service = ex.serviceName == null ? "" : ex.serviceName;
                svc = p.inbound.get(service);
            } else {
                UrlBase ub = normalizeUrlBase(ex.urlBase);
                Service best = null;
                if (!ub.invalid()) {
                    for (Service sv : p.services) {
                        if (sv.base == null || !sv.base.origin.equals(ub.origin())) continue;
                        List<String> bs = sv.base.segs;
                        if (bs.size() > segs.size()) continue;
                        boolean ok = true;
                        for (int i = 0; i < bs.size(); i++) if (!bs.get(i).equals(segs.get(i).dec())) ok = false;
                        if (ok && (best == null || bs.size() > best.base.segs.size())) best = sv;
                    }
                }
                if (best != null) {
                    svc = best;
                    service = best.name;
                    baseCount = best.base.segs.size();
                } else if (ub.invalid()) service = "host:invalid";
                else if (p.hostsAllow.contains(ub.hostport())) service = "host:" + ub.hostport();
                else if (p.hostsAuto || disc != null) {
                    // 3.1, 3.5 (v1.5): the pattern, never the host; also in discovery mode (15)
                    String pat = HostPattern.pattern(ub.host(), ub.port(), ub.ip6());
                    service = pat != null ? "host:" + pat : "host:invalid";
                } else service = "host:unlisted";
            }

            // 3.3 template
            List<Seg> opSegs = segs.subList(baseCount, segs.size());
            String routeSource = "raw";
            if (svc != null && !method.equals("OTHER") && !truncated) {
                if (ex.inbound && ex.frameworkRoute != null && ex.framework != null) {
                    TemplateSeg[] fr = normalizeFrameworkRoute(ex.frameworkRoute, ex.framework);
                    if (fr != null && fr.length == opSegs.size()) {
                        for (Op o : svc.ops) {
                            if (!o.method.equals(method) || o.segs.length != fr.length) continue;
                            boolean ok = true;
                            for (int i = 0; i < fr.length && ok; i++) {
                                TemplateSeg t = o.segs[i];
                                ok = t.lit() != null ? t.lit().equals(fr[i].lit()) : fr[i].param() != null;
                            }
                            if (ok) {
                                op = o;
                                routeSource = "framework";
                                break;
                            }
                        }
                    }
                }
                if (op == null) {
                    Op best = null;
                    for (Op o : svc.ops) {
                        if (!o.method.equals(method) || o.segs.length != opSegs.size()) continue;
                        boolean ok = true;
                        for (int i = 0; i < o.segs.length && ok; i++) {
                            TemplateSeg t = o.segs[i];
                            String sd = opSegs.get(i).dec();
                            ok = t.lit() != null ? t.lit().equals(sd) : sd != null;
                        }
                        if (!ok) continue;
                        if (best == null || o.literals > best.literals || (o.literals == best.literals && Utf8.cmp(o.key, best.key) < 0)) best = o;
                    }
                    if (best != null) {
                        op = best;
                        routeSource = "policy";
                    }
                }
            }

            // 4.2 path
            List<String> outSegs = new ArrayList<>();
            for (int i = 0; i < segs.size(); i++) {
                String dec = segs.get(i).dec();
                if (dec == null) {
                    outSegs.add("{drop:bytes}");
                    continue;
                }
                if (i < baseCount) {
                    outSegs.add(dec);
                    continue;
                }
                if (op != null) {
                    TemplateSeg t = op.segs[i - baseCount];
                    if (t.lit() != null) {
                        outSegs.add(t.lit());
                        continue;
                    }
                    Action action = op.request == null ? null : op.request.path.get(t.param());
                    outSegs.add("{" + strAction(dec, action, true, "req.path." + i) + "}");
                    continue;
                }
                if (p.allow.contains(dec) || (autoWords && Formats.AUTO_WORD.matcher(dec).matches() && Utf8.length(dec) <= 40)) {
                    outSegs.add(dec);
                    continue;
                }
                outSegs.add("{" + strAction(dec, null, true, "req.path." + i) + "}");
            }
            if (truncated) outSegs.add("{trunc}");
            String path = "/" + String.join("/", outSegs);
            String opKey = op != null ? op.key : method + " /" + String.join("/", outSegs.subList(baseCount, outSegs.size()));

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("service", service);
            out.put("op", opKey);
            out.put("route_source", routeSource);
            out.put("sampled_by", by);

            Map<String, Object> req = new LinkedHashMap<>();
            req.put("path", path);
            List<Part> reqGroups = groups(true, -1);
            if (ex.rawQuery != null) {
                Map<String, Object> q = namedMap(parseUrlencoded(ex.rawQuery), reqGroups, "query", "req.query");
                if (!q.isEmpty()) req.put("query", q);
            }
            Headers rh = normalizeHeaders(ex.reqHeaders);
            side(req, true, rh, reqGroups, ex.reqBody, ex.reqBodyTotal, ex.reqBodyConsumed, ex.reqBodyDecoded);
            out.put("req", req);

            resp = true;
            if (ex.netError == null) {
                Map<String, Object> resp = new LinkedHashMap<>();
                List<Part> respGroups = groups(false, ex.status);
                Headers sh = normalizeHeaders(ex.respHeaders);
                side(resp, false, sh, respGroups, ex.respBody, ex.respBodyTotal, ex.respBodyConsumed, ex.respBodyDecoded);
                out.put("resp", resp);
            }
            if (subject != null) out.put("subject", s.token("subject", subject));
            if (disc != null && !disc.isEmpty()) {
                Map<String, Object> d = new LinkedHashMap<>();
                List<String> keys = new ArrayList<>(disc.keySet());
                keys.sort(Utf8::cmp);
                for (String k : keys.subList(0, Math.min(keys.size(), MAX_DISC))) {
                    byte[] kb = Utf8.encode(k);
                    byte[] v = disc.get(k);
                    byte[] in = new byte[kb.length + 1 + v.length];
                    System.arraycopy(kb, 0, in, 0, kb.length);
                    System.arraycopy(v, 0, in, kb.length + 1, v.length);
                    d.put(k, "tkd:" + Base64Url.encode(s.mac("discovery", in), 4));
                }
                out.put("disc", d);
            }
            return out;
        }

        /** Rule groups in precedence order (5.0); null entries are absent groups. */
        List<Part> groups(boolean request, int status) {
            boolean err = !request && status >= 400;
            List<Part> g = new ArrayList<>(5);
            g.add(op == null ? null : (request ? op.request : op.response));
            g.add(err && svc != null ? svc.errors : null);
            g.add(err ? p.globalErrors : null);
            g.add(svc == null ? null : (request ? svc.request : svc.response));
            g.add(request ? p.globalRequest : p.globalResponse);
            return g;
        }

        void side(Map<String, Object> dst, boolean request, Headers h, List<Part> groups, byte[] body, long total, boolean consumed, boolean decoded) {
            String sideName = request ? "req" : "resp";
            // 8.1 headers (cookie / set-cookie never appear)
            List<NamedEntry> hdr = new ArrayList<>();
            for (String name : h.order) {
                if (name.equals("cookie") || name.equals("set-cookie")) continue;
                HdrEntry e = h.map.get(name);
                hdr.add(new NamedEntry(e.origs.size() == 1 ? e.origs.iterator().next() : null, name, joined(e), false));
            }
            Map<String, Object> hm = namedMap(hdr, groups, "headers", sideName + ".headers");
            if (!hm.isEmpty()) dst.put("headers", hm);

            // 8.2 cookies
            List<NamedEntry> ck = new ArrayList<>();
            if (request) {
                HdrEntry e = h.map.get("cookie");
                if (e != null) for (byte[] part : Utf8.split(joined(e), ';')) cookiePart(Utf8.trimOws(part), ck);
            } else {
                HdrEntry e = h.map.get("set-cookie");
                if (e != null) {
                    for (byte[] v : e.values) {
                        int semi = Utf8.indexOf(v, ';');
                        cookiePart(Utf8.trimOws(semi >= 0 ? java.util.Arrays.copyOf(v, semi) : v), ck);
                    }
                }
            }
            Map<String, Object> cm = namedMap(ck, groups, "cookies", sideName + ".cookies");
            if (!cm.isEmpty()) dst.put("cookies", cm);

            String ct = contentType(h);
            if (ct != null) dst.put("ct", ct);
            String kind = treatment(ct);
            HdrEntry cte = h.map.get("content-type");
            byte[] ctRaw = cte == null ? null : joined(cte);
            if (request && "xml".equals(kind)) {
                // 22.2 point 11: SOAPAction header (SOAP 1.1), else the action parameter of the content-type (SOAP 1.2).
                HdrEntry sae = h.map.get("soapaction");
                String sa;
                if (sae == null) sa = Bodies.mediaParams(ctRaw).get("action");
                else {
                    sa = Utf8.decode(joined(sae));
                    if (sa == null) sa = "{*}";
                }
                if (sa != null) {
                    String name = sa.equals("{*}") ? "{*}" : Bodies.soapActionName(sa);
                    if (name != null) dst.put("soap_action", name);
                }
            }
            int saved = maxArray;
            // 5.7.2: with the introspection gate open the response body keeps arrays up to 4096 elements.
            if (!request && gqlGate()) maxArray = Math.max(maxArray, GraphQL.INTROSPECTION_MAX_ARRAY);
            try {
                body(dst, sideName, ct, kind, ctRaw, contentEncoding(h), groups, body == null ? new byte[0] : body, total, consumed, decoded);
            } finally {
                maxArray = saved;
            }
            // 22.1: fmt whenever a body leaves under the XML or multipart treatment
            if (dst.containsKey("body") && ("xml".equals(kind) || "multipart".equals(kind)) && !dst.containsKey("fmt")) dst.put("fmt", kind);
        }

        /** 9.1 and 22.1: json, form, xml, multipart or null (not parsed). */
        String treatment(String ct) {
            if (ct == null) return null;
            if (ct.equals("application/json") || ct.endsWith("+json")) return "json";
            if (ct.equals("application/x-www-form-urlencoded")) return "form";
            Policy.Bodies b = p.bodies;
            if (b.xml() && (ct.equals("application/xml") || ct.equals("text/xml") || ct.endsWith("+xml"))) return "xml";
            if (b.multipart() && ct.equals("multipart/form-data")) return "multipart";
            return null;
        }

        // --- graphql (5.7, spec v1.14) ----------------------------------------------------

        /** The introspection gate: open iff some request value had a graphql rule and all were introspection-only documents. */
        boolean gqlGate() {
            return gqlSeen && !gqlNonIntro;
        }

        /** A request value under a graphql rule without a usable string (not UTF-8, unpaired surrogate, not a string) closes the gate. */
        void gqlUnusable(Action a) {
            if (a != null && a.action.equals("graphql") && !resp) {
                gqlSeen = true;
                gqlNonIntro = true;
            }
        }

        /** graphql action on a well-formed string: the gql: token, or null for the drop form. */
        String graphqlLeaf(String str) {
            if (!resp) {
                gqlSeen = true;
                GraphQL.Result r = GraphQL.shape(str);
                if (r == null) {
                    gqlNonIntro = true;
                    return null;
                }
                if (!r.introspection()) gqlNonIntro = true;
                return "gql:" + r.shape();
            }
            if (gqlGate() && GraphQL.isName(str) && GraphQL.nameSafe(str)) return "gql:" + str;
            return null;
        }

        /** 9.1: an application/graphql body is one string leaf at $ when the winning rule for $ is graphql; null otherwise. */
        String graphqlBody(List<Part> groups, byte[] data) {
            Action a = null;
            for (Part g : groups) {
                if (g == null) continue;
                BodyRule best = null;
                for (BodyRule r : g.body) {
                    if (r.steps.length != 0) continue;
                    if (best == null || Utf8.cmp(r.path, best.path) < 0) best = r;
                }
                if (best != null) {
                    a = best.action;
                    break;
                }
            }
            if (a == null || !a.action.equals("graphql")) return null;
            String str = Utf8.decode(data);
            if (str == null) {
                gqlUnusable(a);
                return "drop:str:invalid";
            }
            return strAction(str, a, false, null);
        }

        // --- body (9) -------------------------------------------------------------------

        void body(Map<String, Object> dst, String sideName, String ct, String kind, byte[] ctRaw, String ce, List<Part> groups, byte[] data, long total, boolean consumed, boolean decoded) {
            int max = p.limits.maxBodyBytes();
            Policy.Bodies bd = p.bodies;
            long tot = total == Exchange.ABSENT ? data.length : total;
            if (!consumed || total == Exchange.UNKNOWN) {
                dst.put("body", "trunc:size");
                dst.put("size", "lmax");
                return;
            }
            if (tot == 0) {
                dst.put("size", "l8");
                return;
            }
            // 22.5: the decoding cap includes the large-body limit.
            int cap = Math.max(max, bd.maxLargeBodyBytes());
            if (ce != null && !ce.equals("identity")) {
                if (!ce.equals("gzip") && !ce.equals("x-gzip") && !ce.equals("deflate")) {
                    dst.put("body", "drop:bytes");
                    return;
                }
                if (!decoded) {
                    BodyDecoder.Result r = BodyDecoder.decode(data, ce.equals("deflate"), cap + 1);
                    if (r.cap) {
                        dst.put("body", "trunc:size");
                        dst.put("size", "lmax");
                        return;
                    }
                    if (r.data == null) {
                        dst.put("body", "drop:bytes");
                        return;
                    }
                    data = r.data;
                    tot = data.length;
                }
            }
            boolean large = false;
            if (tot > max) {
                if (kind == null || tot > bd.maxLargeBodyBytes()) {
                    dst.put("body", "trunc:size");
                    dst.put("size", "lmax");
                    return;
                }
                large = true; // 22.5
            }
            dst.put("size", Formats.lenClass(tot));
            if ("application/graphql".equals(ct) && data.length == tot) {
                // 9.1 and 5.7 (spec v1.14): the whole body is one leaf under a graphql rule on $.
                String g = graphqlBody(groups, data);
                if (g != null) {
                    dst.put("body", g);
                    return;
                }
            }
            if (kind != null && data.length < tot) {
                // 9.1: only a prefix of a parsed body: it cannot be analysed.
                dst.put("body", "trunc:size");
                return;
            }
            if (kind == null) {
                dst.put("body", "drop:bytes:" + Formats.lenClass(tot));
                return;
            }
            switch (kind) {
                case "json" -> {
                    Node root;
                    try {
                        root = Json.parse(data);
                    } catch (Json.JsonError e) {
                        dst.put("body", "trunc:invalid-json");
                        return;
                    }
                    dst.put("body", walkBody(root, groups, sideName, false, large));
                }
                case "form" -> dst.put("body", namedMap(parseUrlencoded(data), groups, "form", sideName + ".body"));
                case "xml" -> {
                    Bodies.Elem root;
                    try {
                        root = Bodies.parseXml(data);
                    } catch (Bodies.InvalidXml e) {
                        dst.put("body", "trunc:invalid-xml");
                        return;
                    }
                    Bodies.XmlTree t = Bodies.xmlTree(root, p.limits.maxDepth());
                    dst.put("fmt", t.fmt());
                    dst.put("body", walkBody(t.tree(), groups, sideName, true, large));
                    List<String[]> entries = t.xmlns();
                    if (!entries.isEmpty()) {
                        Map<String, Object> xmlns = new LinkedHashMap<>();
                        for (String[] en : entries.subList(0, Math.min(entries.size(), MAX_NAMES))) xmlns.put(en[0], en[1]);
                        if (entries.size() > MAX_NAMES) xmlns.put("{trunc}", "trunc:keys:" + Formats.lenClass(entries.size()));
                        dst.put("xmlns", xmlns);
                    }
                }
                default -> { // multipart
                    List<Bodies.MultipartPart> parts;
                    try {
                        parts = Bodies.parseMultipart(data, Bodies.mediaParams(ctRaw).get("boundary"));
                    } catch (Bodies.InvalidMultipart e) {
                        dst.put("body", "trunc:invalid-multipart");
                        return;
                    }
                    List<NamedEntry> entries = new ArrayList<>(parts.size());
                    for (Bodies.MultipartPart mp : parts) {
                        String out = Formats.isLiteralName(mp.name()) ? mp.name() : "{*}";
                        if (mp.isFile()) entries.add(new NamedEntry(mp.name(), out, null, false, Bodies.fileToken(mp.content(), mp.contentType())));
                        else entries.add(new NamedEntry(mp.name(), out, mp.content(), false));
                    }
                    dst.put("body", namedMap(entries, groups, "form", sideName + ".body"));
                }
            }
        }

        Object walkBody(Node root, List<Part> groups, String sideName, boolean xml, boolean large) {
            List<List<BodyRule>> alive = new ArrayList<>();
            for (Part g : groups) alive.add(g == null ? List.of() : g.body);
            walkXml = xml;
            walkLarge = large;
            try {
                return walk(root, 0, alive, disc != null ? sideName + ".body" : null, 0);
            } finally {
                walkXml = false;
                walkLarge = false;
            }
        }

        Object walk(Node node, int pos, List<List<BodyRule>> alive, String dpath, int arrLevel) {
            Policy.Limits lim = p.limits;
            if (node instanceof Obj || node instanceof Arr) {
                if (pos + 1 > lim.maxDepth()) return "trunc:depth";
                // 5.0 explicit drop on a container
                for (int g = 0; g < alive.size(); g++) {
                    boolean hasDrop = false;
                    for (BodyRule r : alive.get(g)) {
                        if (r.steps.length == pos && r.action.action.equals("drop")) {
                            hasDrop = true;
                            break;
                        }
                    }
                    if (!hasDrop) continue;
                    boolean reach = false;
                    for (int h = 0; h <= g && !reach; h++) {
                        for (BodyRule r : alive.get(h)) {
                            if (r.steps.length > pos) {
                                reach = true;
                                break;
                            }
                        }
                    }
                    if (!reach) {
                        if (node instanceof Arr a) return "drop:arr:" + Formats.lenClass(a.items.size());
                        return "drop:obj:" + Formats.lenClass(dedupe((Obj) node).size());
                    }
                    break;
                }
                boolean anyAlive = false;
                for (List<BodyRule> rs : alive) if (!rs.isEmpty()) anyAlive = true;
                if (node instanceof Arr a) {
                    List<Object> res = new ArrayList<>();
                    int arrCap = maxArray;
                    if (walkLarge) arrCap = arrLevel == 0 ? p.bodies.largeArray() : p.bodies.largeNestedArray(); // 22.5
                    int n = Math.min(a.items.size(), arrCap);
                    List<List<BodyRule>> child = alive;
                    if (anyAlive) {
                        child = new ArrayList<>();
                        for (List<BodyRule> rs : alive) {
                            List<BodyRule> f = new ArrayList<>();
                            for (BodyRule r : rs) if (r.steps.length > pos && r.steps[pos].t() == Step.IDX) f.add(r);
                            child.add(f);
                        }
                    }
                    for (int i = 0; i < n; i++) res.add(walk(a.items.get(i), pos + 1, child, dpath == null ? null : dpath + "[*]", arrLevel + 1));
                    if (a.items.size() > arrCap) res.add("trunc:n:" + Formats.lenClass(a.items.size()));
                    return res;
                }
                List<Map.Entry<Str, Node>> members = dedupe((Obj) node);
                Map<String, Object> res = new LinkedHashMap<>();
                List<Object> dyn = new ArrayList<>();
                List<Map.Entry<Str, Node>> kept = members.size() > lim.maxKeys() ? members.subList(0, lim.maxKeys()) : members;
                for (Map.Entry<Str, Node> me : kept) {
                    Str k = me.getKey();
                    boolean literal = !k.bad && (walkXml ? Bodies.xmlKeyIsLiteral(k.s) : Formats.isLiteralName(k.s));
                    List<List<BodyRule>> child = alive;
                    if (anyAlive) {
                        child = new ArrayList<>();
                        for (List<BodyRule> rs : alive) {
                            List<BodyRule> f = new ArrayList<>();
                            for (BodyRule r : rs) {
                                if (r.steps.length <= pos) continue;
                                Step st = r.steps[pos];
                                if (st.t() == Step.ANY || (st.t() == Step.NAME && !k.bad && st.name().equals(k.s))) f.add(r);
                            }
                            child.add(f);
                        }
                    }
                    Object o = walk(me.getValue(), pos + 1, child, dpath == null ? null : dpath + (literal ? "." + k.s : ".*"), arrLevel);
                    if (literal) res.put(k.s, o);
                    else dyn.add(o);
                }
                if (!dyn.isEmpty()) {
                    List<String[]> keyed = new ArrayList<>();
                    Map<String[], Object> back = new java.util.IdentityHashMap<>();
                    for (Object o : dyn) {
                        String[] kk = {Json.writeCanonical(o)};
                        keyed.add(kk);
                        back.put(kk, o);
                    }
                    keyed.sort((x, y) -> Utf8.cmp(x[0], y[0]));
                    List<Object> sorted = new ArrayList<>();
                    for (String[] kk : keyed) sorted.add(back.get(kk));
                    res.put("{*}", sorted);
                }
                if (members.size() > lim.maxKeys()) res.put("{trunc}", "trunc:keys:" + Formats.lenClass(members.size()));
                return res;
            }
            // leaf
            for (List<BodyRule> rs : alive) {
                BodyRule best = null;
                for (BodyRule r : rs) {
                    if (r.steps.length != pos) continue;
                    if (best == null || r.names > best.names || (r.names == best.names && Utf8.cmp(r.path, best.path) < 0)) best = r;
                }
                if (best != null) return leaf(node, best.action, null);
            }
            return leaf(node, null, dpath);
        }

        Object leaf(Node node, Action a, String dpath) {
            // 5.7.1: a request value under a graphql rule that is not a string closes the gate.
            if (!(node instanceof Str)) gqlUnusable(a);
            if (node instanceof Json.Null) {
                if (a != null && a.action.equals("keep")) return Json.NULL;
                if (a == null && dpath != null) discAdd(dpath, "null".getBytes(StandardCharsets.ISO_8859_1));
                return "drop:null";
            }
            if (node instanceof Json.Bool b) {
                if (a != null && a.action.equals("keep")) return b.v;
                if (a == null && dpath != null) discAdd(dpath, (b.v ? "true" : "false").getBytes(StandardCharsets.ISO_8859_1));
                return "drop:bool";
            }
            if (node instanceof Json.Num n) {
                boolean within = Json.lexemeWithinLimits(n.lex);
                String shape = Json.isIntLexeme(n.lex) ? "drop:int" : "drop:dec";
                if (a == null) {
                    if (dpath != null && within) discAdd(dpath, Json.canonicalNumber(n.lex).getBytes(StandardCharsets.ISO_8859_1));
                    return shape;
                }
                if (!within) return shape;
                switch (a.action) {
                    case "keep": return new CNum(Json.canonicalNumber(n.lex));
                    case "hmac": return s.token(a.domain != null ? a.domain : "id", Json.canonicalNumber(n.lex).getBytes(StandardCharsets.ISO_8859_1));
                    case "bucket": return "num".equals(a.kind) ? bucketNum(n.lex, a) : shape;
                    default: return shape;
                }
            }
            Str st = (Str) node;
            if (st.bad) {
                gqlUnusable(a);
                return "drop:str:invalid";
            }
            return strAction(st.s, a, false, dpath);
        }

        /** Action on a string value (named parts, path segments, JSON strings). null = not UTF-8. */
        String strAction(String str, Action a, boolean pathParam, String dpath) {
            if (str == null) {
                gqlUnusable(a);
                return "drop:bytes";
            }
            if (a == null) {
                if (dpath != null && disc != null) discAdd(dpath, Utf8.encode(str));
                return strShape(str);
            }
            switch (a.action) {
                case "keep":
                    if (Utf8.length(str) <= p.limits.keepMaxBytes() && (!pathParam || Formats.PATH_TOKEN.matcher(str).matches())) return "keep:" + str;
                    return strShape(str);
                case "code": {
                    // 5.6: only a code-shaped string within keep_max_bytes leaves (v1.11 shape, or alnum since v1.19).
                    Pattern rx = "alnum".equals(a.shape) ? Formats.CODE_ALNUM : Formats.CODE;
                    if (rx.matcher(str).matches() && str.length() <= p.limits.keepMaxBytes()) return "keep:" + str;
                    return strShape(str);
                }
                case "graphql": {
                    // 5.7 (spec v1.14): request documents leave as their shape, introspection names behind the gate.
                    String g = graphqlLeaf(str);
                    return g != null ? g : strShape(str);
                }
                case "hmac":
                    return s.token(a.domain != null ? a.domain : "id", Utf8.encode(str));
                case "bucket":
                    if ("time".equals(a.kind) && (!pathParam || Formats.PATH_TOKEN.matcher(str).matches())) {
                        String r = bucketTime(str, a.unit == null ? "" : a.unit);
                        return r != null ? r : strShape(str);
                    }
                    return strShape(str);
                default:
                    return strShape(str);
            }
        }

        /** 6.2 for a well-formed string, with the document shape of 22.4 when bodies.docs is on. */
        String strShape(String str) {
            String f = Formats.detectFormat(str);
            if (f != null) return "drop:str:" + f;
            if (p.bodies.docs()) {
                String d = Bodies.base64Doc(str);
                if (d != null) return d;
            }
            return "drop:str:" + Formats.lenClass(Utf8.length(str));
        }

        void discAdd(String path, byte[] value) {
            if (disc == null) return;
            byte[] prev = disc.get(path);
            if (prev == null || Utf8.cmp(value, prev) < 0) disc.put(path, value);
        }

        // --- named parts (8.1-8.3, 9.1 form) ---------------------------------------------

        Action namedRule(List<Part> groups, String section, String name) {
            if (name == null) return null;
            for (Part g : groups) {
                if (g == null) continue;
                if (section.equals("form")) {
                    BodyRule best = null;
                    for (BodyRule r : g.body) {
                        if (r.steps.length != 1) continue;
                        Step st = r.steps[0];
                        if (!(st.t() == Step.ANY || (st.t() == Step.NAME && st.name().equals(name)))) continue;
                        if (best == null || r.names > best.names || (r.names == best.names && Utf8.cmp(r.path, best.path) < 0)) best = r;
                    }
                    if (best != null) return best.action;
                    continue;
                }
                Map<String, Action> m = switch (section) {
                    case "query" -> g.query;
                    case "headers" -> g.headers;
                    default -> g.cookies;
                };
                Action a = m.get(name);
                if (a != null) return a;
            }
            return null;
        }

        Map<String, Object> namedMap(List<NamedEntry> entries, List<Part> groups, String section, String discPrefix) {
            List<String> order = new ArrayList<>();
            Map<String, List<NamedEntry>> byName = new HashMap<>();
            for (NamedEntry e : entries) {
                List<NamedEntry> l = byName.get(e.out);
                if (l == null) {
                    l = new ArrayList<>();
                    byName.put(e.out, l);
                    order.add(e.out);
                }
                l.add(e);
            }
            Map<String, Object> res = new LinkedHashMap<>();
            // After 8.0 every header name has exactly one value: max_array applies to cookies,
            // query and form values only (8.2, 8.3).
            int maxArr = section.equals("headers") ? Integer.MAX_VALUE : maxArray;
            for (String name : order.subList(0, Math.min(order.size(), MAX_NAMES))) {
                List<NamedEntry> list = byName.get(name);
                List<Object> vals = new ArrayList<>();
                // 15: named parts use the output name ({*} when collapsed); form fields use tt-path style.
                String dpath = disc != null ? discPrefix + "." + (section.equals("form") && name.equals("{*}") ? "*" : name) : null;
                for (int i = 0; i < Math.min(list.size(), maxArr); i++) {
                    NamedEntry e = list.get(i);
                    if (e.token != null) {
                        vals.add(e.token);
                        continue;
                    }
                    // Parts without "=" have no name: always drop (no rule can select them).
                    Action a = e.noEq ? null : namedRule(groups, section, e.orig);
                    vals.add(strAction(Utf8.decode(e.value), a, false, dpath));
                }
                if (list.size() > maxArr) vals.add("trunc:n:" + Formats.lenClass(list.size()));
                res.put(name, vals);
            }
            if (order.size() > MAX_NAMES) res.put("{trunc}", new ArrayList<Object>(List.of("trunc:keys:" + Formats.lenClass(order.size()))));
            return res;
        }
    }

    private static List<Map.Entry<Str, Node>> dedupe(Obj o) {
        int n = o.size();
        Map<String, Integer> last = new HashMap<>();
        for (int i = 0; i < n; i++) last.put(o.keys.get(i).s, i);
        List<Map.Entry<Str, Node>> out = new ArrayList<>(last.size());
        for (int i = 0; i < n; i++) {
            if (last.get(o.keys.get(i).s) == i) out.add(Map.entry(o.keys.get(i), o.values.get(i)));
        }
        return out;
    }

    private static void cookiePart(byte[] piece, List<NamedEntry> out) {
        int eq = Utf8.indexOf(piece, '=');
        if (eq < 0) return;
        String name = Utf8.decode(piece, 0, eq);
        out.add(new NamedEntry(name, name != null && Formats.isLiteralName(name) ? name : "{*}",
            java.util.Arrays.copyOfRange(piece, eq + 1, piece.length), false));
    }

    /** 8.3 / 9.1: query string or form body into named entries. */
    private static List<NamedEntry> parseUrlencoded(byte[] raw) {
        List<NamedEntry> out = new ArrayList<>();
        for (byte[] part : Utf8.split(raw, '&')) {
            if (part.length == 0) continue;
            int eq = Utf8.indexOf(part, '=');
            if (eq < 0) {
                out.add(new NamedEntry(null, "{*}", Utf8.pctDecode(part, true), true));
                continue;
            }
            String name = Utf8.decode(Utf8.pctDecode(java.util.Arrays.copyOf(part, eq), true));
            out.add(new NamedEntry(name, name != null && Formats.isLiteralName(name) ? name : "{*}",
                Utf8.pctDecode(java.util.Arrays.copyOfRange(part, eq + 1, part.length), true), false));
        }
        return out;
    }
}
