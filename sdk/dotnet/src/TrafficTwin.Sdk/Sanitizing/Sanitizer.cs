using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace TrafficTwin.Sdk.Sanitizing;

// The sanitizer, docs/spec/sanitizer.md v1.1.1. Input: one normalized exchange (section 1), a verified
// compiled policy, the local HMAC key and the clock. Output: the canonical object of section 2, or
// not_sampled. Guiding rule: in doubt, drop. Any exception escaping from here must be treated by the
// caller as an internal error (no event, `sanitizer_errors` + 1).

internal sealed class HdrEntry
{
    public string Out = "";
    public readonly List<byte[]> Values = new();
    public readonly HashSet<string> Origs = new(StringComparer.Ordinal);
}

internal sealed class Headers
{
    public readonly List<string> Order = new();
    public readonly Dictionary<string, HdrEntry> Map = new(StringComparer.Ordinal);
}

internal sealed class NamedEntry
{
    public string? Orig;
    public string Out = "";
    public byte[] Value = Array.Empty<byte>();
    public bool NoEq;
    /// <summary>A ready output token (multipart file part, 22.3): no rule and no discovery apply.</summary>
    public string? Token;
}

/// <summary>Normalized <c>url_base</c>: <c>Host</c>/<c>Port</c> (port "" when absent or default) and <c>Ip6</c> (the 16 bytes of a bracketed literal) feed 3.5.</summary>
internal readonly record struct UrlBase(bool Invalid, string Origin, string HostPort, string Host = "", string Port = "", byte[]? Ip6 = null);

internal readonly record struct Seg(string? Dec);

internal sealed class Sanitizer
{
    public const int MaxEventBytes = 524288;
    private const int MaxSegments = 32;
    private const int MaxNames = 64;
    private const int MaxDisc = 4096;
    private const int SubjectMax = 8192;

    private static readonly List<BodyRule> NoRules = new();
    private static readonly byte[] SepComma = { (byte)',', (byte)' ' };
    private static readonly byte[] SepSemi = { (byte)';', (byte)' ' };

    internal readonly Policy Policy;
    internal readonly string Kid;
    internal readonly byte[] Key;
    internal readonly int? RateOverrideBp;
    private readonly Func<double>? rand;
    private readonly byte[] epochBuf;

    public Sanitizer(Policy policy, string kid, byte[] key, int? rateOverrideBp = null, Func<double>? rand = null)
    {
        Policy = policy;
        Kid = kid;
        Key = key;
        RateOverrideBp = rateOverrideBp;
        this.rand = rand;
        epochBuf = Utf8Util.Latin1(policy.Epoch);
    }

    // --- header normalization (8.0) ---------------------------------------------------

    public static Headers NormalizeHeaders(List<(string Name, byte[] Value)>? list)
    {
        var h = new Headers();
        if (list == null) return h;
        foreach (var (name, value) in list)
        {
            if (name.Length > 0 && name[0] == ':') continue;
            string lower = Utf8Util.AsciiLower(name);
            string outName = Formats.HeaderOutName(lower);
            if (!h.Map.TryGetValue(outName, out HdrEntry? e))
            {
                e = new HdrEntry { Out = outName };
                h.Map[outName] = e;
                h.Order.Add(outName);
            }
            e.Values.Add(Utf8Util.TrimOws(value));
            e.Origs.Add(lower);
        }
        return h;
    }

    private static byte[] Concat(List<byte[]> values, byte[] sep)
    {
        if (values.Count == 1) return values[0];
        int total = sep.Length * (values.Count - 1);
        foreach (var v in values) total += v.Length;
        var res = new byte[total];
        int o = 0;
        for (int i = 0; i < values.Count; i++)
        {
            if (i > 0) { sep.CopyTo(res, o); o += sep.Length; }
            values[i].CopyTo(res, o);
            o += values[i].Length;
        }
        return res;
    }

    private static byte[] Joined(HdrEntry e) => Concat(e.Values, e.Out == "cookie" ? SepSemi : SepComma);

    /// <summary>Joined value of one exact lowercase header name (subject, baggage).</summary>
    private static byte[]? HeaderValue(List<(string Name, byte[] Value)>? list, string lower)
    {
        if (list == null) return null;
        List<byte[]>? vals = null;
        foreach (var (n, v) in list)
        {
            if (n.Length > 0 && n[0] == ':') continue;
            if (Utf8Util.EqualsAsciiLower(n, lower)) (vals ??= new List<byte[]>()).Add(Utf8Util.TrimOws(v));
        }
        if (vals == null) return null;
        return Concat(vals, lower == "cookie" ? SepSemi : SepComma);
    }

    private static readonly Regex CtRe = Re.Full("[a-z0-9.+-]{1,64}/[a-z0-9.+-]{1,64}");

    /// <summary>8.1.5: <c>ct</c> from the normalized content-type value; null without the header.</summary>
    public static string? ContentType(Headers h)
    {
        if (!h.Map.TryGetValue("content-type", out HdrEntry? e)) return null;
        byte[] v = Joined(e);
        int semi = Array.IndexOf(v, (byte)';');
        if (semi >= 0) v = v.AsSpan(0, semi).ToArray();
        string s = Utf8Util.AsciiLower(Utf8Util.Latin1(Utf8Util.TrimOws(v)));
        return CtRe.IsMatch(s) ? s : "invalid";
    }

    private static string? ContentEncoding(Headers h)
    {
        if (!h.Map.TryGetValue("content-encoding", out HdrEntry? e)) return null;
        return Utf8Util.AsciiLower(Utf8Util.Latin1(Utf8Util.TrimOws(Joined(e))));
    }

    // --- path (4.1) and routing (3) ---------------------------------------------------

    public static (List<Seg> Segs, bool Truncated) DecomposePath(byte[] raw)
    {
        var segs = new List<Seg>();
        bool truncated = false;
        foreach (byte[] s in Utf8Util.Split(raw, 0x2f))
        {
            if (s.Length == 0) continue;
            if (segs.Count == MaxSegments) { truncated = true; break; }
            segs.Add(new Seg(Utf8Util.Decode(Utf8Util.PctDecode(s, false))));
        }
        return (segs, truncated);
    }

    private static readonly Regex UrlBaseRe = Re.Full("([A-Za-z][A-Za-z0-9+.-]*)://(.*)", RegexOptions.Singleline);
    private static readonly Regex BadAuthority = Re.Find("[@/?#]");
    private static readonly Regex PortRe = Re.Full("[0-9]{1,5}");
    private static readonly Regex HostRe = Re.Full("[a-z0-9.-]{1,253}");

    /// <summary>3.1 normalization of <c>url_base</c> (with the IPv6 literals of spec v1.5).</summary>
    public static UrlBase NormalizeUrlBase(string? u)
    {
        var bad = new UrlBase(true, "", "");
        if (u == null) return bad;
        Match m = UrlBaseRe.Match(u);
        if (!m.Success) return bad;
        string scheme = Utf8Util.AsciiLower(m.Groups[1].Value);
        string rest = m.Groups[2].Value;
        if (BadAuthority.IsMatch(rest)) return bad;
        string host;
        string? portText = null;
        byte[]? ip6 = null;
        if (rest.StartsWith('['))
        {
            int end = rest.IndexOf(']');
            if (end < 0) return bad;
            string inner = Utf8Util.AsciiLower(rest.Substring(1, end - 1));
            string after = rest.Substring(end + 1);
            ip6 = HostPattern.ParseIpv6(inner);
            if (ip6 == null) return bad;
            if (after.StartsWith(':')) portText = after.Substring(1);
            else if (after.Length > 0) return bad;
            host = "[" + inner + "]";
        }
        else
        {
            host = rest;
            int c = rest.LastIndexOf(':');
            if (c >= 0)
            {
                host = rest.Substring(0, c);
                portText = rest.Substring(c + 1);
            }
            host = Utf8Util.AsciiLower(host);
            if (!HostRe.IsMatch(host)) return bad;
        }
        string port = "";
        if (portText != null)
        {
            if (!PortRe.IsMatch(portText)) return bad;
            int pn = int.Parse(portText, CultureInfo.InvariantCulture);
            if (pn < 1 || pn > 65535) return bad;
            port = pn.ToString(CultureInfo.InvariantCulture);
            if ((scheme == "http" && pn == 80) || (scheme == "https" && pn == 443)) port = "";
        }
        string hostport = port.Length > 0 ? host + ":" + port : host;
        return new UrlBase(false, scheme + "://" + hostport, hostport, host, port, ip6);
    }

    public static readonly HashSet<string> Frameworks = new(StringComparer.Ordinal)
    {
        "express", "koa", "fastify", "flask", "fastapi", "django", "spring", "jaxrs",
        "aspnetcore", "gin", "chi", "nethttp", "laravel", "symfony",
    };

    private const string PName = "[A-Za-z_][A-Za-z0-9_]{0,63}";
    private static readonly Regex ReColon = Re.Full(":(" + PName + ")");
    private static readonly Regex ReColonRegex = Re.Full(":(" + PName + @")\((.*)\)", RegexOptions.Singleline);
    private static readonly Regex ReAngle = Re.Full("<(?:([A-Za-z_][A-Za-z0-9_]*):)?(" + PName + ")>");
    private static readonly Regex ReBrace = Re.Full(@"\{(" + PName + @")\}");
    private static readonly Regex ReBraceConv = Re.Full(@"\{(" + PName + @"):(.+)\}", RegexOptions.Singleline);
    private static readonly Regex ReBraceSymfony = Re.Full(@"\{(" + PName + @")<(.+)>\}", RegexOptions.Singleline);
    private static readonly Regex RePName = Re.Full(PName);
    private static readonly Regex ReEscape = Re.Find(@"\\.");
    private static readonly Regex ReInnerParam = Re.Find(":[A-Za-z_]");

    /// <summary>One segment of a framework route: the parameter name, or null when it is not a parameter syntax of that framework.</summary>
    private static string? FrameworkParam(string fw, string s)
    {
        Match m;
        switch (fw)
        {
            case "express":
            case "koa":
            case "fastify":
                if ((m = ReColon.Match(s)).Success) return m.Groups[1].Value;
                // ":name(regex)"; a regex holding another ":param" means several parameters.
                if ((m = ReColonRegex.Match(s)).Success && !ReInnerParam.IsMatch(ReEscape.Replace(m.Groups[2].Value, ""))) return m.Groups[1].Value;
                return null;
            case "gin":
                return (m = ReColon.Match(s)).Success ? m.Groups[1].Value : null;
            case "flask":
            case "django":
                m = ReAngle.Match(s);
                return m.Success && !(m.Groups[1].Success && m.Groups[1].Value == "path") ? m.Groups[2].Value : null;
            case "fastapi":
                if ((m = ReBrace.Match(s)).Success) return m.Groups[1].Value;
                m = ReBraceConv.Match(s);
                return m.Success && m.Groups[2].Value != "path" ? m.Groups[1].Value : null;
            case "spring":
            case "chi":
                if ((m = ReBrace.Match(s)).Success) return m.Groups[1].Value;
                return (m = ReBraceConv.Match(s)).Success ? m.Groups[1].Value : null;
            case "jaxrs":
                {
                    // "{ name : regex }": spaces around the name and the colon are ignored.
                    if (s.Length < 2 || s[0] != '{' || s[s.Length - 1] != '}') return null;
                    string inner = s.Substring(1, s.Length - 2);
                    int c = inner.IndexOf(':');
                    string name = (c < 0 ? inner : inner.Substring(0, c)).Trim();
                    if (!RePName.IsMatch(name)) return null;
                    if (c >= 0 && inner.Substring(c + 1).Trim().Length == 0) return null;
                    return name;
                }
            case "aspnetcore":
                if ((m = ReBrace.Match(s)).Success) return m.Groups[1].Value;
                // "{name:constraint[:constraint...]}"; "?" marks an optional parameter, "=" a default.
                m = ReBraceConv.Match(s);
                return m.Success && !m.Groups[2].Value.EndsWith('?') && !m.Groups[2].Value.Contains('=') ? m.Groups[1].Value : null;
            case "nethttp":
            case "laravel":
                return (m = ReBrace.Match(s)).Success ? m.Groups[1].Value : null;
            case "symfony":
                if ((m = ReBrace.Match(s)).Success) return m.Groups[1].Value;
                return (m = ReBraceSymfony.Match(s)).Success ? m.Groups[1].Value : null;
            default:
                return null;
        }
    }

    /// <summary>
    /// 3.4 with A-FRAMEWORK-ID (normative since 1.1.1): normalizes <paramref name="route"/> with the table of <paramref name="framework"/>.
    /// Every segment must be a parameter syntax of that framework or a literal of the operation-key grammar; anything else fails.
    /// </summary>
    public static List<TemplateSeg>? NormalizeFrameworkRoute(string route, string framework)
    {
        if (!Frameworks.Contains(framework)) return null;
        var raw = route.Split('/').Where(s => s.Length > 0).ToList();
        var outp = new List<TemplateSeg>();
        for (int i = 0; i < raw.Count; i++)
        {
            string s = raw[i];
            if (framework == "nethttp" && s == "{$}" && i == raw.Count - 1) continue; // exact-match marker
            string? p = FrameworkParam(framework, s);
            if (p != null) outp.Add(new TemplateSeg(null, p));
            else if (Formats.IsPathToken(s)) outp.Add(new TemplateSeg(s, null));
            else return null;
        }
        return outp.Count > MaxSegments ? null : outp;
    }

    // --- buckets (5.5) ------------------------------------------------------------------

    private static long FloorDiv(long a, long b)
    {
        long q = a / b;
        return (a % b != 0 && ((a < 0) != (b < 0))) ? q - 1 : q;
    }

    private static (long Y, long M, long D) CivilFromDays(long z)
    {
        z += 719468;
        long era = FloorDiv(z, 146097);
        long doe = z - era * 146097;
        long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        long y = yoe + era * 400;
        long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        long mp = (5 * doy + 2) / 153;
        long d = doy - (153 * mp + 2) / 5 + 1;
        long m = mp + (mp < 10 ? 3 : -9);
        return (m <= 2 ? y + 1 : y, m, d);
    }

    private static readonly Regex TimeParse = Re.Full("([0-9]{4})-([0-9]{2})-([0-9]{2})(?:[Tt ]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\\.[0-9]{1,9})?(?:[Zz]|([+-])([0-9]{2}):([0-9]{2})))?");

    public static string? BucketTime(string s, string unit)
    {
        if (!Formats.IsPrintableAscii(s) || !(Formats.IsDateTime(s) || Formats.IsDate(s))) return null;
        Match m = TimeParse.Match(s);
        if (!m.Success) return null;
        static long N(Group g) => long.Parse(g.Value, CultureInfo.InvariantCulture);
        long y = N(m.Groups[1]), mo = N(m.Groups[2]), d = N(m.Groups[3]);
        long h = m.Groups[4].Success ? N(m.Groups[4]) : 0;
        long mi = m.Groups[5].Success ? N(m.Groups[5]) : 0;
        long se = m.Groups[6].Success ? N(m.Groups[6]) : 0;
        if (y < 1 || y > 9999 || mo < 1 || mo > 12 || d < 1) return null;
        bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        long[] dim = { 31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        if (d > dim[mo - 1] || h > 23 || mi > 59 || se > 59) return null;
        long off = 0;
        if (m.Groups[7].Success)
        {
            long oh = N(m.Groups[8]), om = N(m.Groups[9]);
            if (oh > 23 || om > 59) return null;
            off = (oh * 60 + om) * (m.Groups[7].Value == "+" ? 1 : -1);
        }
        long total = Parsing.DaysFromCivil(y, mo, d) * 1440 + h * 60 + mi - off;
        long days = FloorDiv(total, 1440);
        long hour = FloorDiv(total - days * 1440, 60);
        var (uy, um, ud) = CivilFromDays(days);
        if (uy < 1 || uy > 9999) return null;
        string P2(long n) => n.ToString("D2", CultureInfo.InvariantCulture);
        string ys = uy.ToString("D4", CultureInfo.InvariantCulture);
        switch (unit)
        {
            case "year": return "time:" + ys;
            case "month": return "time:" + ys + "-" + P2(um);
            case "day": return "time:" + ys + "-" + P2(um) + "-" + P2(ud);
            case "hour": return "time:" + ys + "-" + P2(um) + "-" + P2(ud) + "T" + P2(hour);
            default: return null;
        }
    }

    public static string BucketNum(string lex, RuleAction a)
    {
        var b = a.Bounds!;
        double v = double.Parse(lex, NumberStyles.Float, CultureInfo.InvariantCulture);
        if (v < b[0].D) return "num:<" + b[0].Canon;
        for (int i = 0; i + 1 < b.Count; i++)
        {
            if (v >= b[i].D && v < b[i + 1].D) return "num:" + b[i].Canon + "-" + b[i + 1].Canon;
        }
        return "num:>=" + b[b.Count - 1].Canon;
    }

    // --- HMAC ----------------------------------------------------------------------------

    public byte[] Mac(string domain, ReadOnlySpan<byte> value)
    {
        byte[] dom = Utf8Util.Latin1(domain);
        var msg = new byte[epochBuf.Length + 1 + dom.Length + 1 + value.Length];
        int o = 0;
        epochBuf.CopyTo(msg, o); o += epochBuf.Length;
        msg[o++] = 0;
        dom.CopyTo(msg, o); o += dom.Length;
        msg[o++] = 0;
        value.CopyTo(msg.AsSpan(o));
        return HMACSHA256.HashData(Key, msg);
    }

    public string Token(string domain, ReadOnlySpan<byte> value) =>
        "tk1:" + Kid + ":" + Utf8Util.B64UrlNoPad(Mac(domain, value).AsSpan(0, 16));

    public int RateBp() => RateOverrideBp.HasValue ? Math.Min(RateOverrideBp.Value, Policy.RateBp) : Policy.RateBp;

    // --- subject (11) -------------------------------------------------------------------

    public byte[]? SubjectValue(List<(string Name, byte[] Value)>? reqHeaders)
    {
        SubjectSpec? spec = Policy.Subject;
        if (spec == null) return null;
        byte[]? raw = null;
        if (spec.From == "header")
        {
            raw = HeaderValue(reqHeaders, Utf8Util.AsciiLower(spec.Name));
        }
        else
        {
            byte[]? cookie = HeaderValue(reqHeaders, "cookie");
            if (cookie != null)
            {
                foreach (byte[] p in Utf8Util.Split(cookie, 0x3b))
                {
                    byte[] piece = Utf8Util.TrimOws(p);
                    int eq = Array.IndexOf(piece, (byte)'=');
                    if (eq < 0) continue;
                    if (Utf8Util.Decode(piece.AsSpan(0, eq)) == spec.Name)
                    {
                        raw = piece.AsSpan(eq + 1).ToArray();
                        break;
                    }
                }
            }
        }
        if (raw == null || raw.Length == 0 || raw.Length > SubjectMax) return null;
        string? s = Utf8Util.Decode(raw);
        if (s == null || s.Length == 0) return null;
        if (spec.From == "header" && spec.JsonPath != null) return JsonMember(s, spec.JsonPath);
        if (spec.From == "header")
        {
            // /^bearer[ \t]+/i
            if (s.Length > 6 && string.Equals(s.Substring(0, 6), "bearer", StringComparison.OrdinalIgnoreCase) && (s[6] == ' ' || s[6] == '\t'))
            {
                int k = 6;
                while (k < s.Length && (s[k] == ' ' || s[k] == '\t')) k++;
                s = s.Substring(k);
                if (s.Length == 0) return null;
            }
        }
        if (spec.JwtClaim == null) return Utf8Util.Utf8(s);
        string[] parts = s.Split('.');
        if (parts.Length != 3) return null;
        string payload = parts[1];
        // padding "=" at most twice, only at the end
        int pad = 0;
        while (pad < 2 && payload.Length - pad > 0 && payload[payload.Length - 1 - pad] == '=') pad++;
        payload = payload.Substring(0, payload.Length - pad);
        byte[]? bytes = Utf8Util.B64UrlDecodeStrict(payload);
        if (bytes == null) return null;
        JNode doc;
        try { doc = JsonParser.Parse(bytes); }
        catch (JsonException2) { return null; }
        if (doc is not JObj obj) return null;
        JNode? v = null;
        foreach (var kv in obj.Members)
        {
            if (!kv.Key.Bad && kv.Key.S == spec.JwtClaim) v = kv.Value;
        }
        if (v == null) return null;
        if (v is JStr js) return js.S.Length != 0 && !js.Bad ? Utf8Util.Utf8(js.S) : null;
        if (v is JNum jn) return JsonNumbers.WithinLimits(jn.Lex) ? Utf8Util.Latin1(JsonNumbers.Canonical(jn.Lex)) : null;
        return null;
    }

    /// <summary>
    /// Standard or URL-safe base64 (never mixed), with or without padding (at most two '=' at the end, then a length
    /// that is a multiple of 4). Null on any other character or an impossible length.
    /// </summary>
    private static byte[]? B64Any(string s)
    {
        int end = s.Length;
        for (int k = 0; k < 2 && end > 0 && s[end - 1] == '='; k++) end--;
        if (end == 0 || (end != s.Length && s.Length % 4 != 0) || end % 4 == 1) return null;
        bool std = false, url = false;
        for (int i = 0; i < end; i++)
        {
            char c = s[i];
            if (c == '+' || c == '/') std = true;
            else if (c == '-' || c == '_') url = true;
            else if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) return null;
        }
        if (std && url) return null;
        var outp = new byte[end * 3 / 4];
        int o = 0, acc = 0, bits = 0;
        for (int i = 0; i < end; i++)
        {
            char ch = s[i];
            int v = ch >= 'A' && ch <= 'Z' ? ch - 'A'
                : ch >= 'a' && ch <= 'z' ? ch - 'a' + 26
                : ch >= '0' && ch <= '9' ? ch - '0' + 52
                : ch == '-' || ch == '+' ? 62
                : 63;
            acc = ((acc << 6) | v) & 0xffff;
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                outp[o++] = (byte)((acc >> bits) & 0xff);
            }
        }
        return outp;
    }

    /// <summary>
    /// Spec v1.18 (sanitizer.md 11, step 4 bis): the subject is a member of a header whose value is a JSON object, or
    /// base64/base64url of one. No bearer prefix is stripped; the dot always separates members.
    /// </summary>
    private static byte[]? JsonMember(string s, string path)
    {
        int a = 0, b = s.Length;
        while (a < b && (s[a] == ' ' || s[a] == '\t')) a++;
        while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) b--;
        string t = s.Substring(a, b - a);
        if (t.Length == 0) return null;
        byte[]? bytes = t[0] == '{' ? Utf8Util.Utf8(t) : B64Any(t);
        if (bytes == null) return null;
        JNode v;
        try { v = JsonParser.Parse(bytes); }
        catch (JsonException2) { return null; }
        foreach (string name in path.Split('.'))
        {
            if (v is not JObj obj) return null;
            JNode? found = null;
            foreach (var kv in obj.Members)
            {
                if (!kv.Key.Bad && kv.Key.S == name) found = kv.Value;
            }
            if (found == null) return null;
            v = found;
        }
        if (v is JStr js) return js.S.Length != 0 && !js.Bad ? Utf8Util.Utf8(js.S) : null;
        if (v is JNum jn) return JsonNumbers.WithinLimits(jn.Lex) ? Utf8Util.Latin1(JsonNumbers.Canonical(jn.Lex)) : null;
        return null;
    }

    // --- sampling (12) ------------------------------------------------------------------

    private bool HashSample(string domain, ReadOnlySpan<byte> value)
    {
        byte[] mac = Mac(domain, value);
        uint u = ((uint)mac[0] << 24) | ((uint)mac[1] << 16) | ((uint)mac[2] << 8) | mac[3];
        return u % 10000 < (uint)RateBp();
    }

    private bool RandomSample()
    {
        int rate = RateBp();
        if (rate <= 0) return false;
        if (rate >= 10000) return true;
        double r = rand != null ? rand() : Random.Shared.NextDouble();
        return Math.Floor(r * 10000) < rate;
    }

    /// <summary>Sampling decision for an exchange (needs only the request line and headers).</summary>
    public Decision Decide(bool inbound, string? serviceName, List<(string Name, byte[] Value)>? reqHeaders, string? traceId, bool? inherited, byte[]? subject = null, bool subjectComputed = false)
    {
        if (inbound)
        {
            ServiceRules? svc = null;
            if (serviceName != null) Policy.InboundServices.TryGetValue(serviceName, out svc);
            if (Policy.TrustBaggage && svc is { Internal: true })
            {
                byte[]? bag = HeaderValue(reqHeaders, "baggage");
                string? s = bag != null ? Utf8Util.Decode(bag) : null;
                if (s != null)
                {
                    foreach (string member in s.Split(','))
                    {
                        string kv = Utf8Util.TrimOwsStr(member.Split(';')[0]);
                        int eq = kv.IndexOf('=');
                        if (eq < 0) continue;
                        string k = Utf8Util.TrimOwsStr(kv.Substring(0, eq));
                        string v = Utf8Util.TrimOwsStr(kv.Substring(eq + 1));
                        if (k == "tt.s" && (v == "0" || v == "1")) return new Decision(v == "1", "baggage");
                    }
                }
            }
            byte[]? subj = subjectComputed ? subject : SubjectValue(reqHeaders);
            if (subj is { Length: > 0 }) return new Decision(HashSample("sample", subj), "subject");
        }
        else if (inherited.HasValue)
        {
            return new Decision(inherited.Value, "inherited");
        }
        if (!string.IsNullOrEmpty(traceId))
            return new Decision(HashSample("sample-trace", Utf8Util.Latin1(Utf8Util.AsciiLower(traceId))), "trace");
        return new Decision(RandomSample(), "random");
    }

    // --- whole exchange -----------------------------------------------------------------

    public SanitizeResult Run(Exchange ex, double now, Decision? decision = null)
    {
        byte[]? subject = SubjectValue(ex.ReqHeaders);
        Decision d = decision ?? Decide(ex.Inbound, ex.ServiceName, ex.ReqHeaders, ex.TraceId, ex.Inherited, subject, true);
        if (!d.Sampled) return new SanitizeResult { Outcome = Outcome.NotSampled, SampledBy = d.By };
        var run = new RunState(this, ex, now);
        Dictionary<string, object?> outp = run.Build(d.By, subject);
        // Each top-level member is serialized once; the source reuses these parts to assemble the full event.
        var parts = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var kv in outp) parts[kv.Key] = Canonical.Write(kv.Value);
        string canonical = Canonical.Compose(parts);
        // 10.3, measured on the sanitizer output (A-EVENT-SIZE-BASE). Canonical output is ASCII.
        if (canonical.Length > MaxEventBytes)
        {
            foreach (string step in new[] { "req", "resp", "disc" })
            {
                bool changed;
                if (step == "disc") changed = outp.Remove("disc");
                else changed = outp.TryGetValue(step, out object? side) && side is Dictionary<string, object?> sm && sm.ContainsKey("body") && Replace(sm);
                if (!changed) continue;
                if (outp.TryGetValue(step, out object? val)) parts[step] = Canonical.Write(val);
                else parts.Remove(step);
                canonical = Canonical.Compose(parts);
                if (canonical.Length <= MaxEventBytes) break;
            }
            if (canonical.Length > MaxEventBytes) return new SanitizeResult { Outcome = Outcome.TooLarge, SampledBy = d.By };
        }
        return new SanitizeResult { Outcome = Outcome.Event, Out = outp, Parts = parts, Canonical = canonical, SampledBy = d.By };

        static bool Replace(Dictionary<string, object?> side)
        {
            side["body"] = "trunc:size";
            return true;
        }
    }

    /// <summary>9.0 decoding, one level, with an output cap (A-GZIP-STRICT).</summary>
    internal static BodyDecoder.Result DecodeBody(byte[] data, bool zlibFormat, long cap) => BodyDecoder.Decode(data, zlibFormat, cap);

    // --- named parts -------------------------------------------------------------------

    private static void CookiePart(byte[] piece, List<NamedEntry> outp)
    {
        int eq = Array.IndexOf(piece, (byte)'=');
        if (eq < 0) return;
        string? name = Utf8Util.Decode(piece.AsSpan(0, eq));
        outp.Add(new NamedEntry
        {
            Orig = name,
            Out = name != null && Formats.IsLiteralName(name) ? name : "{*}",
            Value = piece.AsSpan(eq + 1).ToArray(),
            NoEq = false,
        });
    }

    /// <summary>8.3 / 9.1: query string or form body into named entries.</summary>
    public static List<NamedEntry> ParseUrlencoded(byte[] raw)
    {
        var outp = new List<NamedEntry>();
        foreach (byte[] part in Utf8Util.Split(raw, 0x26))
        {
            if (part.Length == 0) continue;
            int eq = Array.IndexOf(part, (byte)'=');
            if (eq < 0)
            {
                outp.Add(new NamedEntry { Orig = null, Out = "{*}", Value = Utf8Util.PctDecode(part, true), NoEq = true });
                continue;
            }
            string? name = Utf8Util.Decode(Utf8Util.PctDecode(part.AsSpan(0, eq).ToArray(), true));
            outp.Add(new NamedEntry
            {
                Orig = name,
                Out = name != null && Formats.IsLiteralName(name) ? name : "{*}",
                Value = Utf8Util.PctDecode(part.AsSpan(eq + 1).ToArray(), true),
                NoEq = false,
            });
        }
        return outp;
    }

    /// <summary>Per-exchange state.</summary>
    private sealed class RunState
    {
        private readonly Sanitizer s;
        private readonly Exchange ex;
        private readonly double now;
        private readonly Policy p;
        private readonly Dictionary<string, byte[]>? disc;
        private readonly bool autoWords;
        private ServiceRules? svc;
        private Op? op;
        // Array limit of the body being sanitized: limits.max_array, raised for a response body with the GraphQL gate open (5.7.2).
        private int maxArray;
        // GraphQL (5.7): onResponse is set while the response is sanitized; gqlSeen and gqlNonIntro record the request values with a graphql rule.
        private bool onResponse;
        private bool gqlSeen;
        private bool gqlNonIntro;

        public RunState(Sanitizer s, Exchange ex, double now)
        {
            this.s = s;
            this.ex = ex;
            this.now = now;
            p = s.Policy;
            disc = p.DiscoveryActive(now) ? new Dictionary<string, byte[]>(StringComparer.Ordinal) : null;
            autoWords = p.AutoWordsActive(now);
            maxArray = p.Limits.MaxArray;
        }

        public Dictionary<string, object?> Build(string by, byte[]? subject)
        {
            string method = Utf8Util.AsciiUpper(ex.Method ?? "");
            if (!IsMethod(method)) method = "OTHER";
            var (segs, truncated) = DecomposePath(ex.RawPath);

            // 3.1 service
            string service;
            int baseCount = 0;
            if (ex.Inbound)
            {
                service = ex.ServiceName ?? "";
                p.InboundServices.TryGetValue(service, out svc);
            }
            else
            {
                UrlBase ub = NormalizeUrlBase(ex.UrlBase);
                ServiceRules? best = null;
                if (!ub.Invalid)
                {
                    foreach (ServiceRules cand in p.Services)
                    {
                        if (cand.BaseOrigin == null || cand.BaseOrigin != ub.Origin) continue;
                        var bs = cand.BaseSegs!;
                        if (bs.Count > segs.Count) continue;
                        bool ok = true;
                        for (int i = 0; i < bs.Count; i++)
                        {
                            if (segs[i].Dec != bs[i]) ok = false;
                        }
                        if (ok && (best == null || bs.Count > best.BaseSegs!.Count)) best = cand;
                    }
                }
                if (best != null)
                {
                    svc = best;
                    service = best.Name;
                    baseCount = best.BaseSegs!.Count;
                }
                else if (ub.Invalid) service = "host:invalid";
                else if (p.HostsAllow.Contains(ub.HostPort)) service = "host:" + ub.HostPort;
                else if (p.HostsAuto || disc != null)
                {
                    // 3.1, 3.5 (v1.5): the pattern, never the host; also in discovery mode (15)
                    string? pat = HostPattern.Pattern(ub.Host, ub.Port, ub.Ip6);
                    service = pat != null ? "host:" + pat : "host:invalid";
                }
                else service = "host:unlisted";
            }

            // 3.3 template
            var opSegs = segs.Skip(baseCount).ToList();
            string routeSource = "raw";
            if (svc != null && method != "OTHER" && !truncated)
            {
                if (ex.Inbound && ex.FrameworkRoute != null && ex.Framework != null)
                {
                    var fr = NormalizeFrameworkRoute(ex.FrameworkRoute, ex.Framework);
                    if (fr != null && fr.Count == opSegs.Count)
                    {
                        foreach (Op cand in svc.Ops)
                        {
                            if (cand.Method != method || cand.Segs.Count != fr.Count) continue;
                            bool same = true;
                            for (int i = 0; i < cand.Segs.Count && same; i++)
                            {
                                var t = cand.Segs[i];
                                same = t.Lit != null ? fr[i].Lit == t.Lit : fr[i].Param != null;
                            }
                            if (same)
                            {
                                op = cand;
                                routeSource = "framework";
                                break;
                            }
                        }
                    }
                }
                if (op == null)
                {
                    Op? best = null;
                    foreach (Op cand in svc.Ops)
                    {
                        if (cand.Method != method || cand.Segs.Count != opSegs.Count) continue;
                        bool ok = true;
                        for (int i = 0; i < cand.Segs.Count && ok; i++)
                        {
                            var t = cand.Segs[i];
                            string? sd = opSegs[i].Dec;
                            ok = t.Lit != null ? sd == t.Lit : sd != null;
                        }
                        if (!ok) continue;
                        if (best == null || cand.Literals > best.Literals || (cand.Literals == best.Literals && Utf8Util.CmpUtf8(cand.Key, best.Key) < 0)) best = cand;
                    }
                    if (best != null)
                    {
                        op = best;
                        routeSource = "policy";
                    }
                }
            }

            // 4.2 path
            var outSegs = new List<string>();
            for (int i = 0; i < segs.Count; i++)
            {
                string? dec = segs[i].Dec;
                if (dec == null) { outSegs.Add("{drop:bytes}"); continue; }
                if (i < baseCount) { outSegs.Add(dec); continue; }
                if (op != null)
                {
                    var t = op.Segs[i - baseCount];
                    if (t.Lit != null) { outSegs.Add(t.Lit); continue; }
                    RuleAction? action = null;
                    op.Request?.PathParams.TryGetValue(t.Param!, out action);
                    outSegs.Add("{" + StrAction(dec, action, true, "req.path." + i.ToString(CultureInfo.InvariantCulture)) + "}");
                    continue;
                }
                if (p.Allow.Contains(dec) || (autoWords && Formats.IsAutoWord(dec) && Utf8Util.Utf8Length(dec) <= 40))
                {
                    outSegs.Add(dec);
                    continue;
                }
                outSegs.Add("{" + StrAction(dec, null, true, "req.path." + i.ToString(CultureInfo.InvariantCulture)) + "}");
            }
            if (truncated) outSegs.Add("{trunc}");
            string path = "/" + string.Join("/", outSegs);
            string opKey = op != null ? op.Key : method + " /" + string.Join("/", outSegs.Skip(baseCount));

            var outp = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["service"] = service,
                ["op"] = opKey,
                ["route_source"] = routeSource,
                ["sampled_by"] = by,
            };

            // request
            var req = new Dictionary<string, object?>(StringComparer.Ordinal) { ["path"] = path };
            var reqGroups = Groups(false, null);
            if (ex.RawQuery != null)
            {
                var q = NamedMap(ParseUrlencoded(ex.RawQuery), reqGroups, "query", "req.query");
                if (q.Count > 0) req["query"] = q;
            }
            Headers rh = NormalizeHeaders(ex.ReqHeaders);
            Side(req, "req", rh, reqGroups, ex.ReqBody, ex.ReqBodyTotal, ex.ReqBodyConsumed, ex.ReqBodyDecoded);
            string? sa = SoapAction(rh);
            if (sa != null) req["soap_action"] = sa;
            outp["req"] = req;

            onResponse = true;
            if (ex.NetError == null)
            {
                var resp = new Dictionary<string, object?>(StringComparer.Ordinal);
                var respGroups = Groups(true, ex.Status);
                Headers sh = NormalizeHeaders(ex.RespHeaders);
                Side(resp, "resp", sh, respGroups, ex.RespBody, ex.RespBodyTotal, ex.RespBodyConsumed, ex.RespBodyDecoded);
                outp["resp"] = resp;
            }
            if (subject != null) outp["subject"] = s.Token("subject", subject);
            if (disc != null && disc.Count > 0)
            {
                var d = new Dictionary<string, object?>(StringComparer.Ordinal);
                var keys = disc.Keys.ToList();
                keys.Sort(Utf8Util.CmpUtf8);
                foreach (string k in keys.Take(MaxDisc))
                {
                    byte[] kb = Utf8Util.Utf8(k);
                    byte[] val = disc[k];
                    var buf = new byte[kb.Length + 1 + val.Length];
                    kb.CopyTo(buf, 0);
                    buf[kb.Length] = 0;
                    val.CopyTo(buf, kb.Length + 1);
                    d[k] = "tkd:" + Utf8Util.B64UrlNoPad(s.Mac("discovery", buf).AsSpan(0, 4));
                }
                outp["disc"] = d;
            }
            return outp;
        }

        private static bool IsMethod(string m)
        {
            if (m.Length < 1 || m.Length > 16) return false;
            foreach (char c in m)
            {
                if (c < 'A' || c > 'Z') return false;
            }
            return true;
        }

        private List<Part?> Groups(bool response, int? status)
        {
            bool err = response && status.HasValue && status.Value >= 400;
            return new List<Part?>
            {
                response ? op?.Response : op?.Request,
                err ? svc?.Errors : null,
                err ? p.GlobalErrors : null,
                response ? svc?.Response : svc?.Request,
                response ? p.GlobalResponse : p.GlobalRequest,
            };
        }

        private void Side(Dictionary<string, object?> dst, string side, Headers h, List<Part?> groups, byte[]? body, long? total, bool? consumed, bool? decoded)
        {
            // 8.1 headers (cookie / set-cookie never appear)
            var hdrEntries = new List<NamedEntry>();
            foreach (string name in h.Order)
            {
                if (name == "cookie" || name == "set-cookie") continue;
                HdrEntry e = h.Map[name];
                hdrEntries.Add(new NamedEntry { Orig = e.Origs.Count == 1 ? e.Origs.First() : null, Out = name, Value = Joined(e), NoEq = false });
            }
            var hm = NamedMap(hdrEntries, groups, "headers", side + ".headers");
            if (hm.Count > 0) dst["headers"] = hm;

            // 8.2 cookies
            var ck = new List<NamedEntry>();
            if (side == "req")
            {
                if (h.Map.TryGetValue("cookie", out HdrEntry? e))
                {
                    foreach (byte[] part in Utf8Util.Split(Joined(e), 0x3b)) CookiePart(Utf8Util.TrimOws(part), ck);
                }
            }
            else
            {
                if (h.Map.TryGetValue("set-cookie", out HdrEntry? e))
                {
                    foreach (byte[] v in e.Values)
                    {
                        int semi = Array.IndexOf(v, (byte)';');
                        CookiePart(Utf8Util.TrimOws(semi >= 0 ? v.AsSpan(0, semi).ToArray() : v), ck);
                    }
                }
            }
            var cm = NamedMap(ck, groups, "cookies", side + ".cookies");
            if (cm.Count > 0) dst["cookies"] = cm;

            string? ct = ContentType(h);
            if (ct != null) dst["ct"] = ct;
            // 5.7.2: an introspection result keeps its arrays (response body only).
            if (onResponse && GqlGate()) maxArray = Math.Max(p.Limits.MaxArray, GraphQL.IntrospectionMaxArray);
            try { Body(dst, side, h, ct, ContentEncoding(h), groups, body ?? Array.Empty<byte>(), total, consumed, decoded); }
            finally { maxArray = p.Limits.MaxArray; }
        }

        /// <summary>9.1 and 22.1: json, form, xml, multipart, or null (not parsed).</summary>
        private string? Treatment(string? ct)
        {
            if (ct == null) return null;
            if (ct == "application/json" || ct.EndsWith("+json", StringComparison.Ordinal)) return "json";
            if (ct == "application/x-www-form-urlencoded") return "form";
            if (p.Bodies.Xml && (ct == "application/xml" || ct == "text/xml" || ct.EndsWith("+xml", StringComparison.Ordinal))) return "xml";
            if (p.Bodies.Multipart && ct == "multipart/form-data") return "multipart";
            return null;
        }

        /// <summary>22.2 point 11: the SOAP operation name of the request, or null.</summary>
        private string? SoapAction(Headers h)
        {
            if (Treatment(ContentType(h)) != "xml") return null;
            string? raw;
            if (h.Map.TryGetValue("soapaction", out HdrEntry? e)) raw = Utf8Util.Decode(Joined(e)) ?? "{*}";
            else
            {
                byte[]? ctv = h.Map.TryGetValue("content-type", out HdrEntry? c) ? Joined(c) : null;
                raw = MediaParams.Parse(ctv).GetValueOrDefault("action");
            }
            if (raw == null) return null;
            return raw == "{*}" ? "{*}" : Xml.SoapActionName(raw);
        }

        // --- body (9) ---

        private void Body(Dictionary<string, object?> dst, string side, Headers h, string? ct, string? ce, List<Part?> groups, byte[] data, long? total, bool? consumed, bool? decoded)
        {
            string? kind = Treatment(ct);
            BodyInner(dst, side, h, ct, kind, ce, groups, data, total, consumed, decoded);
            // 22.1: fmt whenever a body leaves under the XML or multipart treatment
            if (dst.ContainsKey("body") && (kind == "xml" || kind == "multipart") && !dst.ContainsKey("fmt")) dst["fmt"] = kind;
        }

        private void BodyInner(Dictionary<string, object?> dst, string side, Headers h, string? ct, string? kind, string? ce, List<Part?> groups, byte[] data, long? total, bool? consumed, bool? decoded)
        {
            long max = p.Limits.MaxBodyBytes;
            long largeMax = p.Bodies.MaxLargeBodyBytes;
            long tot = total ?? data.Length;
            if (consumed == false || tot == Exchange.UnknownTotal)
            {
                dst["body"] = "trunc:size";
                dst["size"] = "lmax";
                return;
            }
            if (tot == 0)
            {
                dst["size"] = "l8";
                return;
            }
            if (ce != null && ce != "identity")
            {
                if (ce != "gzip" && ce != "x-gzip" && ce != "deflate")
                {
                    dst["body"] = "drop:bytes";
                    return;
                }
                if (decoded != true)
                {
                    // 22.5: the decoding cap includes the large limit
                    var r = DecodeBody(data, ce == "deflate", Math.Max(max, largeMax) + 1);
                    if (r.Status == BodyDecoder.Status.Cap)
                    {
                        dst["body"] = "trunc:size";
                        dst["size"] = "lmax";
                        return;
                    }
                    if (r.Status == BodyDecoder.Status.Error)
                    {
                        dst["body"] = "drop:bytes";
                        return;
                    }
                    data = r.Data!;
                    tot = data.Length;
                }
            }
            bool large = false;
            if (tot > max)
            {
                if (kind == null || tot > largeMax)
                {
                    dst["body"] = "trunc:size";
                    dst["size"] = "lmax";
                    return;
                }
                large = true; // 22.5
            }
            dst["size"] = Formats.LenClass(tot);
            if (ct == "application/graphql" && data.Length == tot && RootRule(groups) is { Kind: ActionKind.Graphql } ga)
            {
                // 9.1 (spec v1.14): the whole body is one string leaf at $.
                string? text = Utf8Util.Decode(data);
                if (text == null)
                {
                    GqlUnusable(ga);
                    dst["body"] = "drop:str:invalid";
                }
                else dst["body"] = StrAction(text, ga, false, null);
                return;
            }
            if (kind != null && data.Length < tot)
            {
                // only a prefix of a parsed body: it cannot be analysed (9.1)
                dst["body"] = "trunc:size";
                return;
            }
            string? dpath = disc != null ? side + ".body" : null;
            switch (kind)
            {
                case "json":
                    {
                        JNode root;
                        try { root = JsonParser.Parse(data); }
                        catch (JsonException2)
                        {
                            dst["body"] = "trunc:invalid-json";
                            return;
                        }
                        dst["body"] = Walk(root, 0, Alive(groups), dpath, false, large, 0);
                        return;
                    }
                case "form":
                    dst["body"] = NamedMap(ParseUrlencoded(data), groups, "form", side + ".body");
                    return;
                case "xml":
                    {
                        XElem root;
                        try { root = Xml.Parse(data); }
                        catch (InvalidBodyException)
                        {
                            dst["body"] = "trunc:invalid-xml";
                            return;
                        }
                        var (tree, entries, fmt) = Xml.Tree(root, p.Limits.MaxDepth);
                        dst["fmt"] = fmt;
                        dst["body"] = Walk(tree, 0, Alive(groups), dpath, true, large, 0);
                        if (entries.Count > 0)
                        {
                            var xmlns = new Dictionary<string, object?>(StringComparer.Ordinal);
                            foreach (var (path, token) in entries.Take(MaxNames)) xmlns[path] = token;
                            if (entries.Count > MaxNames) xmlns["{trunc}"] = "trunc:keys:" + Formats.LenClass(entries.Count);
                            dst["xmlns"] = xmlns;
                        }
                        return;
                    }
                case "multipart":
                    {
                        byte[]? ctv = h.Map.TryGetValue("content-type", out HdrEntry? c) ? Joined(c) : null;
                        List<MultipartPart> parts;
                        try { parts = Multipart.Parse(data, MediaParams.Parse(ctv).GetValueOrDefault("boundary")); }
                        catch (InvalidBodyException)
                        {
                            dst["body"] = "trunc:invalid-multipart";
                            return;
                        }
                        var entries = new List<NamedEntry>(parts.Count);
                        foreach (MultipartPart part in parts)
                        {
                            entries.Add(new NamedEntry
                            {
                                Orig = part.Name,
                                Out = Formats.IsLiteralName(part.Name) ? part.Name : "{*}",
                                Value = part.IsFile ? Array.Empty<byte>() : part.Content,
                                Token = part.IsFile ? Multipart.FileToken(part.Content, part.Ct) : null,
                            });
                        }
                        dst["body"] = NamedMap(entries, groups, "form", side + ".body");
                        return;
                    }
                default:
                    dst["body"] = "drop:bytes:" + Formats.LenClass(tot);
                    return;
            }
        }

        private static List<BodyRule>[] Alive(List<Part?> groups)
        {
            var alive = new List<BodyRule>[groups.Count];
            for (int gi = 0; gi < alive.Length; gi++) alive[gi] = groups[gi]?.Body ?? NoRules;
            return alive;
        }

        private static List<KeyValuePair<JStr, JNode>> Dedupe(List<KeyValuePair<JStr, JNode>> m)
        {
            if (m.Count < 2) return m;
            var last = new Dictionary<string, int>(StringComparer.Ordinal);
            for (int i = 0; i < m.Count; i++) last[m[i].Key.S] = i;
            if (last.Count == m.Count) return m;
            var res = new List<KeyValuePair<JStr, JNode>>(last.Count);
            for (int i = 0; i < m.Count; i++)
            {
                if (last[m[i].Key.S] == i) res.Add(m[i]);
            }
            return res;
        }

        /// <summary>
        /// 9.2-9.4 on a JSON or XML tree. <paramref name="xml"/> selects the key rule of 22.2 point 8; <paramref name="large"/> the
        /// array caps of 22.5, by array ancestry (<paramref name="arrLevel"/> = number of array ancestors).
        /// </summary>
        private object? Walk(JNode node, int pos, List<BodyRule>[] alive, string? dpath, bool xml, bool large, int arrLevel)
        {
            Limits lim = p.Limits;
            if (node is JObj || node is JArr)
            {
                if (pos + 1 > lim.MaxDepth) return "trunc:depth";
                // 5.0 explicit drop on a container
                for (int g = 0; g < alive.Length; g++)
                {
                    bool hasDrop = false;
                    foreach (BodyRule r in alive[g])
                    {
                        if (r.Steps.Count == pos && r.Action.Kind == ActionKind.Drop) { hasDrop = true; break; }
                    }
                    if (!hasDrop) continue;
                    bool reach = false;
                    for (int h = 0; h <= g && !reach; h++)
                    {
                        foreach (BodyRule r in alive[h])
                        {
                            if (r.Steps.Count > pos) { reach = true; break; }
                        }
                    }
                    if (!reach)
                    {
                        if (node is JArr arr0) return "drop:arr:" + Formats.LenClass(arr0.Items.Count);
                        return "drop:obj:" + Formats.LenClass(Dedupe(((JObj)node).Members).Count);
                    }
                    break;
                }
                bool anyAlive = false;
                foreach (var rs in alive)
                {
                    if (rs.Count > 0) { anyAlive = true; break; }
                }
                if (node is JArr arr)
                {
                    var res = new List<object?>();
                    int cap = maxArray;
                    if (large) cap = arrLevel == 0 ? p.Bodies.LargeArray : p.Bodies.LargeNestedArray;
                    int n = Math.Min(arr.Items.Count, cap);
                    List<BodyRule>[] child = alive;
                    if (anyAlive)
                    {
                        child = new List<BodyRule>[alive.Length];
                        for (int g = 0; g < alive.Length; g++)
                        {
                            var l = new List<BodyRule>();
                            foreach (BodyRule r in alive[g])
                            {
                                if (r.Steps.Count > pos && r.Steps[pos].Kind == StepKind.Idx) l.Add(r);
                            }
                            child[g] = l;
                        }
                    }
                    for (int i = 0; i < n; i++) res.Add(Walk(arr.Items[i], pos + 1, child, dpath == null ? null : dpath + "[*]", xml, large, arrLevel + 1));
                    if (arr.Items.Count > cap) res.Add("trunc:n:" + Formats.LenClass(arr.Items.Count));
                    return res;
                }
                var obj = (JObj)node;
                var members = Dedupe(obj.Members);
                var resMap = new Dictionary<string, object?>(StringComparer.Ordinal);
                var dyn = new List<object?>();
                var kept = members.Count > lim.MaxKeys ? members.Take(lim.MaxKeys).ToList() : members;
                foreach (var kv in kept)
                {
                    JStr k = kv.Key;
                    bool literal = !k.Bad && (xml ? Xml.KeyIsLiteral(k.S) : Formats.IsLiteralName(k.S));
                    List<BodyRule>[] child = alive;
                    if (anyAlive)
                    {
                        child = new List<BodyRule>[alive.Length];
                        for (int g = 0; g < alive.Length; g++)
                        {
                            var l = new List<BodyRule>();
                            foreach (BodyRule r in alive[g])
                            {
                                if (r.Steps.Count <= pos) continue;
                                Step st = r.Steps[pos];
                                if (st.Kind == StepKind.Any || (st.Kind == StepKind.Name && !k.Bad && st.Name == k.S)) l.Add(r);
                            }
                            child[g] = l;
                        }
                    }
                    object? o = Walk(kv.Value, pos + 1, child, dpath == null ? null : dpath + (literal ? "." + k.S : ".*"), xml, large, arrLevel);
                    if (literal) resMap[k.S] = o;
                    else dyn.Add(o);
                }
                if (dyn.Count > 0)
                {
                    var keyed = dyn.Select(o => (Key: Canonical.Write(o), Val: o)).ToList();
                    keyed.Sort((a, b) => Utf8Util.CmpUtf8(a.Key, b.Key));
                    resMap["{*}"] = keyed.Select(x => x.Val).ToList();
                }
                if (members.Count > lim.MaxKeys) resMap["{trunc}"] = "trunc:keys:" + Formats.LenClass(members.Count);
                return resMap;
            }
            // leaf
            foreach (var rs in alive)
            {
                BodyRule? best = null;
                foreach (BodyRule r in rs)
                {
                    if (r.Steps.Count != pos) continue;
                    if (best == null || r.Names > best.Names || (r.Names == best.Names && Utf8Util.CmpUtf8(r.Path, best.Path) < 0)) best = r;
                }
                if (best != null) return Leaf(node, best.Action, null);
            }
            return Leaf(node, null, dpath);
        }

        private object? Leaf(JNode node, RuleAction? a, string? dpath)
        {
            if (node is not JStr) GqlUnusable(a); // a graphql rule on a number, boolean or null
            switch (node)
            {
                case JNull:
                    if (a?.Kind == ActionKind.Keep) return null;
                    if (a == null && dpath != null) DiscAdd(dpath, Utf8Util.Latin1("null"));
                    return "drop:null";
                case JBool b:
                    if (a?.Kind == ActionKind.Keep) return b.V;
                    if (a == null && dpath != null) DiscAdd(dpath, Utf8Util.Latin1(b.V ? "true" : "false"));
                    return "drop:bool";
                case JNum n:
                    {
                        bool within = JsonNumbers.WithinLimits(n.Lex);
                        string shape = JsonNumbers.IsIntLexeme(n.Lex) ? "drop:int" : "drop:dec";
                        if (a == null)
                        {
                            if (dpath != null && within) DiscAdd(dpath, Utf8Util.Latin1(JsonNumbers.Canonical(n.Lex)));
                            return shape;
                        }
                        if (!within) return shape;
                        if (a.Kind == ActionKind.Keep) return new CNum(JsonNumbers.Canonical(n.Lex));
                        if (a.Kind == ActionKind.Hmac) return s.Token(a.Domain ?? "id", Utf8Util.Latin1(JsonNumbers.Canonical(n.Lex)));
                        if (a.Kind == ActionKind.Bucket && a.BucketKind == "num") return BucketNum(n.Lex, a);
                        return shape;
                    }
                case JStr str:
                    if (str.Bad)
                    {
                        GqlUnusable(a);
                        return "drop:str:invalid";
                    }
                    return StrAction(str.S, a, false, dpath);
                default:
                    return "drop:null";
            }
        }

        /// <summary>Action on a string value (named parts, path segments, JSON strings). null = not UTF-8.</summary>
        private string StrAction(string? str, RuleAction? a, bool pathParam, string? dpath)
        {
            if (str == null)
            {
                GqlUnusable(a);
                return "drop:bytes";
            }
            if (a == null)
            {
                if (dpath != null && disc != null) DiscAdd(dpath, Utf8Util.Utf8(str));
                return Shape(str);
            }
            switch (a.Kind)
            {
                case ActionKind.Keep:
                    if (Utf8Util.Utf8Length(str) <= p.Limits.KeepMaxBytes && (!pathParam || Formats.IsPathToken(str))) return "keep:" + str;
                    return Shape(str);
                case ActionKind.Code:
                    // 5.6 (spec v1.11): only a code-shaped string within keep_max_bytes leaves; v1.19 adds the shape alnum.
                    if ((a.Alnum ? Formats.IsCodeAlnum(str) : Formats.IsCode(str)) && str.Length <= p.Limits.KeepMaxBytes) return "keep:" + str;
                    return Shape(str);
                case ActionKind.Graphql:
                    return GraphqlLeaf(str);
                case ActionKind.Hmac:
                    return s.Token(a.Domain ?? "id", Utf8Util.Utf8(str));
                case ActionKind.Bucket:
                    if (a.BucketKind == "time" && (!pathParam || Formats.IsPathToken(str))) return BucketTime(str, a.Unit ?? "") ?? Shape(str);
                    return Shape(str);
                default:
                    return Shape(str);
            }
        }

        /// <summary>6.2 for a well-formed string, with the document shape of 22.4 when <c>bodies.docs</c> is on.</summary>
        private string Shape(string str)
        {
            if (p.Bodies.Docs && Formats.DetectFormat(str) == null)
            {
                string? d = Docs.Base64Doc(str);
                if (d != null) return d;
            }
            return Formats.StrShape(str);
        }

        /// <summary>
        /// 5.7: request side, a document leaves as <c>gql:</c> and its shape and is recorded for the gate; response side,
        /// with the gate open, a GraphQL name passing the name rule leaves as <c>gql:</c> and the name. Otherwise the drop form.
        /// </summary>
        private string GraphqlLeaf(string str)
        {
            if (!onResponse)
            {
                gqlSeen = true;
                var res = GraphQL.Shape(str);
                if (res == null)
                {
                    gqlNonIntro = true;
                    return Shape(str);
                }
                if (!res.Value.Introspection) gqlNonIntro = true;
                return "gql:" + res.Value.Shape;
            }
            if (GqlGate() && GraphQL.IsName(str) && GraphQL.NameSafe(str)) return "gql:" + str;
            return Shape(str);
        }

        /// <summary>The introspection gate: at least one request value had a graphql rule, and all were introspection-only documents.</summary>
        private bool GqlGate() => gqlSeen && !gqlNonIntro;

        /// <summary>A request value under a graphql rule without usable text (not a string, not UTF-8, lone surrogate) closes the gate.</summary>
        private void GqlUnusable(RuleAction? a)
        {
            if (a?.Kind == ActionKind.Graphql && !onResponse) gqlSeen = gqlNonIntro = true;
        }

        /// <summary>The winning body rule for <c>$</c> (5.0), as the leaf case of <see cref="Walk"/> picks it.</summary>
        private static RuleAction? RootRule(List<Part?> groups)
        {
            foreach (Part? g in groups)
            {
                if (g == null) continue;
                BodyRule? best = null;
                foreach (BodyRule r in g.Body)
                {
                    if (r.Steps.Count != 0) continue;
                    if (best == null || r.Names > best.Names || (r.Names == best.Names && Utf8Util.CmpUtf8(r.Path, best.Path) < 0)) best = r;
                }
                if (best != null) return best.Action;
            }
            return null;
        }

        private void DiscAdd(string path, byte[] value)
        {
            if (disc == null) return;
            if (!disc.TryGetValue(path, out byte[]? prev) || value.AsSpan().SequenceCompareTo(prev) < 0) disc[path] = value;
        }

        // --- named parts (8.1-8.3, 9.1 form) ---

        private RuleAction? NamedRule(List<Part?> groups, string section, string? name)
        {
            if (name == null) return null;
            foreach (Part? g in groups)
            {
                if (g == null) continue;
                if (section == "form")
                {
                    BodyRule? best = null;
                    foreach (BodyRule r in g.Body)
                    {
                        if (r.Steps.Count != 1) continue;
                        Step st = r.Steps[0];
                        if (!(st.Kind == StepKind.Any || (st.Kind == StepKind.Name && st.Name == name))) continue;
                        if (best == null || r.Names > best.Names || (r.Names == best.Names && Utf8Util.CmpUtf8(r.Path, best.Path) < 0)) best = r;
                    }
                    if (best != null) return best.Action;
                    continue;
                }
                Dictionary<string, RuleAction> map = section switch
                {
                    "query" => g.Query,
                    "headers" => g.Headers,
                    _ => g.Cookies,
                };
                if (map.TryGetValue(name, out RuleAction? a)) return a;
            }
            return null;
        }

        private Dictionary<string, object?> NamedMap(List<NamedEntry> entries, List<Part?> groups, string section, string discPrefix)
        {
            var order = new List<string>();
            var byName = new Dictionary<string, List<NamedEntry>>(StringComparer.Ordinal);
            foreach (NamedEntry e in entries)
            {
                if (!byName.TryGetValue(e.Out, out List<NamedEntry>? l))
                {
                    l = new List<NamedEntry>();
                    byName[e.Out] = l;
                    order.Add(e.Out);
                }
                l.Add(e);
            }
            var res = new Dictionary<string, object?>(StringComparer.Ordinal);
            // After 8.0 every header name has exactly one value: max_array applies to cookies, query and form values only (8.2, 8.3).
            int maxArr = section == "headers" ? int.MaxValue : maxArray;
            foreach (string name in order.Take(MaxNames))
            {
                var list = byName[name];
                var vals = new List<object?>();
                // 15: named parts use the output name ({*} when collapsed); form fields use tt-path style.
                string? dpath = disc != null ? discPrefix + "." + (section == "form" && name == "{*}" ? "*" : name) : null;
                for (int i = 0; i < Math.Min(list.Count, maxArr); i++)
                {
                    NamedEntry e = list[i];
                    if (e.Token != null)
                    {
                        vals.Add(e.Token);
                        continue;
                    }
                    // Parts without "=" have no name: always drop (no rule can select them).
                    RuleAction? a = e.NoEq ? null : NamedRule(groups, section, e.Orig);
                    vals.Add(StrAction(Utf8Util.Decode(e.Value), a, false, dpath));
                }
                if (list.Count > maxArr) vals.Add("trunc:n:" + Formats.LenClass(list.Count));
                res[name] = vals;
            }
            if (order.Count > MaxNames) res["{trunc}"] = new List<object?> { "trunc:keys:" + Formats.LenClass(order.Count) };
            return res;
        }
    }
}
