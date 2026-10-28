using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace TrafficTwin.Sdk.Sanitizing;

/// <summary>Why a source does not capture (heartbeat states of api/fleet-api.v1.openapi.yaml).</summary>
public sealed class RefusedException : Exception
{
    public string Code { get; }
    public string Detail { get; }

    public RefusedException(string code, string detail = "") : base(code + (detail.Length > 0 ? ": " + detail : ""))
    {
        Code = code;
        Detail = detail;
    }
}

internal sealed record Bound(string Canon, double D);

internal enum ActionKind { Drop, Keep, Hmac, Bucket, Code, Graphql }

internal sealed class RuleAction
{
    public ActionKind Kind;
    public string? Domain;
    /// <summary>"num" or "time" for buckets.</summary>
    public string? BucketKind;
    public List<Bound>? Bounds;
    public string? Unit;
    /// <summary>Code with the shape <c>alnum</c> (sanitizer.md 5.6, spec v1.19).</summary>
    public bool Alnum;

    public static readonly RuleAction Drop = new() { Kind = ActionKind.Drop };
    public static readonly RuleAction Keep = new() { Kind = ActionKind.Keep };
    public static readonly RuleAction Code = new() { Kind = ActionKind.Code };
    public static readonly RuleAction CodeAlnum = new() { Kind = ActionKind.Code, Alnum = true };
    public static readonly RuleAction Graphql = new() { Kind = ActionKind.Graphql };
}

internal enum StepKind { Name, Any, Idx }

internal readonly record struct Step(StepKind Kind, string? Name);

internal sealed class BodyRule
{
    public string Path = "";
    public List<Step> Steps = new();
    public int Names;
    public RuleAction Action = RuleAction.Drop;
}

internal sealed class Part
{
    public Dictionary<string, RuleAction> Query = new(StringComparer.Ordinal);
    public Dictionary<string, RuleAction> Headers = new(StringComparer.Ordinal);
    public Dictionary<string, RuleAction> Cookies = new(StringComparer.Ordinal);
    public Dictionary<string, RuleAction> PathParams = new(StringComparer.Ordinal);
    public List<BodyRule> Body = new();
}

internal readonly record struct TemplateSeg(string? Lit, string? Param);

internal sealed class Op
{
    public string Key = "";
    public string Method = "";
    public List<TemplateSeg> Segs = new();
    public int Literals;
    public Part? Request;
    public Part? Response;
}

internal sealed class ServiceRules
{
    public string Name = "";
    public bool Inbound;
    public bool Internal;
    public string? BaseOrigin;
    public List<string>? BaseSegs;
    public Part? Request;
    public Part? Response;
    public Part? Errors;
    public List<Op> Ops = new();
}

internal sealed record Limits(long MaxBodyBytes, int MaxDepth, int MaxArray, int MaxKeys, int KeepMaxBytes)
{
    public static readonly Limits Default = new(1048576, 32, 32, 256, 64);
}

/// <summary>The <c>bodies</c> switches of spec v1.19 (sanitizer.md 22.1); absent = everything off.</summary>
internal sealed record BodiesConfig(bool Xml, bool Multipart, bool Docs, long MaxLargeBodyBytes, int LargeArray, int LargeNestedArray)
{
    public static readonly BodiesConfig Off = new(false, false, false, 0, 0, 0);
}

/// <summary><c>JsonPath</c> (spec v1.18): dotted path of members inside a header whose value is a JSON object, or base64 of one.</summary>
internal sealed record SubjectSpec(string From, string Name, string? JwtClaim, string? JsonPath = null);

/// <summary>Ready-to-use compiled policy (policy.md 2).</summary>
internal sealed class Policy
{
    private const double DayMs = 86_400_000;

    public readonly string PolicyId;
    public readonly long Version;
    public readonly long IssuedSeq;
    public readonly double CreatedAt;
    public readonly double NotAfter;
    public readonly List<string> Groups;
    public readonly string Kid;
    public readonly List<string> AcceptKids;
    public readonly string Epoch;
    public readonly SubjectSpec? Subject;
    public readonly int RateBp;
    public readonly bool TrustBaggage;
    public readonly HashSet<string> PropagateTo;
    public readonly bool AutoWords;
    public readonly double AutoWordsExpiresAt;
    public readonly HashSet<string> Allow;
    public readonly HashSet<string> HostsAllow;
    /// <summary>Spec v1.5: <c>hosts.discovery</c> is <c>auto</c> (default, also when absent) rather than <c>off</c>.</summary>
    public readonly bool HostsAuto;
    public readonly Limits Limits;
    /// <summary>Spec v1.19 (sanitizer.md 22).</summary>
    public readonly BodiesConfig Bodies;
    public readonly bool DiscoveryEnabled;
    public readonly double DiscoveryExpiresAt;
    public readonly Part? GlobalRequest, GlobalResponse, GlobalErrors;
    public readonly List<ServiceRules> Services = new();
    public readonly Dictionary<string, ServiceRules> InboundServices = new(StringComparer.Ordinal);
    public readonly HashSet<string> BaseHosts = new(StringComparer.Ordinal);
    /// <summary>SHA-256 of the body bytes, when known (<c>sha256:&lt;hex&gt;</c>).</summary>
    public string Hash = "";

    public Policy(Dictionary<string, object?> b)
    {
        PolicyId = Plain.Str(b.GetValueOrDefault("policy_id"), "");
        Version = (long)Plain.Num(b.GetValueOrDefault("version"), 0);
        IssuedSeq = (long)Plain.Num(b.GetValueOrDefault("issued_seq"), 0);
        CreatedAt = Parsing.ParseTime(b.GetValueOrDefault("created_at"));
        NotAfter = Parsing.ParseTime(b.GetValueOrDefault("not_after"));
        var targets = Plain.Obj(b.GetValueOrDefault("targets"));
        Groups = Plain.Arr(targets?.GetValueOrDefault("groups")).Select(g => Plain.Str(g, "")).ToList();
        var hmac = Plain.Obj(b.GetValueOrDefault("hmac")) ?? new Dictionary<string, object?>();
        Kid = Plain.Str(hmac.GetValueOrDefault("kid"), "");
        AcceptKids = Plain.Arr(hmac.GetValueOrDefault("accept_kids")).Select(k => Plain.Str(k, "")).ToList();
        Epoch = Plain.Str(hmac.GetValueOrDefault("epoch"), "");
        var subj = Plain.Obj(Plain.Obj(b.GetValueOrDefault("identity"))?.GetValueOrDefault("subject"));
        if (subj != null)
        {
            Subject = new SubjectSpec(Plain.Str(subj.GetValueOrDefault("from"), "header"), Plain.Str(subj.GetValueOrDefault("name"), ""),
                subj.GetValueOrDefault("jwt_claim") is string jc ? jc : null,
                subj.GetValueOrDefault("json_path") is string jp ? jp : null);
        }
        var sampling = Plain.Obj(b.GetValueOrDefault("sampling")) ?? new Dictionary<string, object?>();
        RateBp = (int)Plain.Num(sampling.GetValueOrDefault("rate_bp"), 0);
        TrustBaggage = sampling.GetValueOrDefault("trust_baggage") is true;
        PropagateTo = new HashSet<string>(Plain.Arr(sampling.GetValueOrDefault("propagate_to")).Select(h => Plain.Str(h, "")), StringComparer.Ordinal);
        var seg = Plain.Obj(b.GetValueOrDefault("segments")) ?? new Dictionary<string, object?>();
        AutoWords = seg.GetValueOrDefault("auto_words") is true;
        AutoWordsExpiresAt = Parsing.ParseTime(seg.GetValueOrDefault("auto_words_expires_at"));
        Allow = new HashSet<string>(Plain.Arr(seg.GetValueOrDefault("allow")).Select(x => Plain.Str(x, "")), StringComparer.Ordinal);
        HostsAllow = new HashSet<string>(Plain.Arr(seg.GetValueOrDefault("hosts_allow")).Select(x => Plain.Str(x, "")), StringComparer.Ordinal);
        HostsAuto = Plain.Obj(b.GetValueOrDefault("hosts"))?.GetValueOrDefault("discovery") as string != "off";
        var lim = Plain.Obj(b.GetValueOrDefault("limits")) ?? new Dictionary<string, object?>();
        var dl = Limits.Default;
        Limits = new Limits(
            (long)Plain.Num(lim.GetValueOrDefault("max_body_bytes"), dl.MaxBodyBytes),
            (int)Plain.Num(lim.GetValueOrDefault("max_depth"), dl.MaxDepth),
            (int)Plain.Num(lim.GetValueOrDefault("max_array"), dl.MaxArray),
            (int)Plain.Num(lim.GetValueOrDefault("max_keys"), dl.MaxKeys),
            (int)Plain.Num(lim.GetValueOrDefault("keep_max_bytes"), dl.KeepMaxBytes));
        var bd = Plain.Obj(b.GetValueOrDefault("bodies"));
        Bodies = bd == null ? BodiesConfig.Off : new BodiesConfig(
            bd.GetValueOrDefault("xml") is true,
            bd.GetValueOrDefault("multipart") is true,
            bd.GetValueOrDefault("docs") is true,
            (long)Plain.Num(bd.GetValueOrDefault("max_large_body_bytes"), 0),
            (int)Plain.Num(bd.GetValueOrDefault("large_array"), 0),
            (int)Plain.Num(bd.GetValueOrDefault("large_nested_array"), 0));
        var disc = Plain.Obj(b.GetValueOrDefault("discovery"));
        DiscoveryEnabled = disc?.GetValueOrDefault("enabled") is true;
        DiscoveryExpiresAt = Parsing.ParseTime(disc?.GetValueOrDefault("expires_at"));
        var g2 = Plain.Obj(b.GetValueOrDefault("global")) ?? new Dictionary<string, object?>();
        GlobalRequest = Parsing.ParsePart(g2.GetValueOrDefault("request"));
        GlobalResponse = Parsing.ParsePart(g2.GetValueOrDefault("response"));
        GlobalErrors = Parsing.ParsePart(g2.GetValueOrDefault("errors"));
        foreach (object? s in Plain.Arr(b.GetValueOrDefault("services")))
        {
            var so = Plain.Obj(s);
            if (so == null) continue;
            var m = Plain.Obj(so.GetValueOrDefault("match")) ?? new Dictionary<string, object?>();
            var svc = new ServiceRules
            {
                Name = Plain.Str(so.GetValueOrDefault("name"), ""),
                Inbound = m.GetValueOrDefault("inbound") is true,
                Internal = m.GetValueOrDefault("internal") is true,
                Request = Parsing.ParsePart(so.GetValueOrDefault("request")),
                Response = Parsing.ParsePart(so.GetValueOrDefault("response")),
                Errors = Parsing.ParsePart(so.GetValueOrDefault("errors")),
            };
            if (m.GetValueOrDefault("base") is string baseStr)
            {
                var (origin, segs) = Parsing.SplitBase(baseStr);
                svc.BaseOrigin = origin;
                svc.BaseSegs = segs;
                int sc = origin.IndexOf("://", StringComparison.Ordinal);
                string auth = sc >= 0 ? origin.Substring(sc + 3) : origin;
                BaseHosts.Add(auth);
                BaseHosts.Add(Regex.Replace(auth, ":[0-9]+\\z", ""));
            }
            foreach (object? o in Plain.Arr(so.GetValueOrDefault("ops")))
            {
                var oo = Plain.Obj(o);
                if (oo == null) continue;
                Op? op = Parsing.ParseOpKey(Plain.Str(oo.GetValueOrDefault("op"), ""));
                if (op == null) continue;
                op.Request = Parsing.ParsePart(oo.GetValueOrDefault("request"));
                op.Response = Parsing.ParsePart(oo.GetValueOrDefault("response"));
                svc.Ops.Add(op);
            }
            Services.Add(svc);
            if (svc.Inbound && !InboundServices.ContainsKey(svc.Name)) InboundServices[svc.Name] = svc;
        }
    }

    /// <summary>
    /// Bytes of a body the capture layer keeps (9.0, 22.5): <c>max(limits.max_body_bytes, bodies.max_large_body_bytes) + 1</c>;
    /// the rest is only counted.
    /// </summary>
    public long CaptureLimit => Math.Max(Limits.MaxBodyBytes, Bodies.MaxLargeBodyBytes) + 1;

    /// <summary>4.3: auto words active at <paramref name="now"/> (epoch ms).</summary>
    public bool AutoWordsActive(double now) =>
        AutoWords && !double.IsNaN(now) && now < AutoWordsExpiresAt && now < CreatedAt + 7 * DayMs;

    /// <summary>15: discovery active at <paramref name="now"/> (epoch ms).</summary>
    public bool DiscoveryActive(double now) =>
        DiscoveryEnabled && !double.IsNaN(now) && now < DiscoveryExpiresAt && now < CreatedAt + 7 * DayMs;
}

internal static class Parsing
{
    private static readonly Regex Rfc3339 = Re.Full("([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\\.[0-9]+)?([Zz]|([+-])([0-9]{2}):([0-9]{2}))");

    internal static long DaysFromCivil(long y, long m, long d)
    {
        y -= m <= 2 ? 1 : 0;
        long era = (long)Math.Floor(y / 400.0);
        long yoe = y - era * 400;
        long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
        long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * 146097 + doe - 719468;
    }

    /// <summary>RFC 3339 timestamp to epoch milliseconds; NaN when absent or malformed.</summary>
    public static double ParseTime(object? v)
    {
        if (v is not string s) return double.NaN;
        Match m = Rfc3339.Match(s);
        if (!m.Success) return double.NaN;
        long y = long.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
        long mo = long.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture);
        long d = long.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture);
        long h = long.Parse(m.Groups[4].Value, CultureInfo.InvariantCulture);
        long mi = long.Parse(m.Groups[5].Value, CultureInfo.InvariantCulture);
        long se = long.Parse(m.Groups[6].Value, CultureInfo.InvariantCulture);
        if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60) return double.NaN;
        double ms = (double)DaysFromCivil(y, mo, d) * 86_400_000 + h * 3_600_000 + mi * 60_000 + se * 1000;
        if (m.Groups[7].Success)
        {
            double frac = double.Parse("0" + m.Groups[7].Value, CultureInfo.InvariantCulture);
            ms += Math.Floor(frac * 1000);
        }
        if (m.Groups[9].Success)
        {
            double off = (long.Parse(m.Groups[10].Value, CultureInfo.InvariantCulture) * 60 + long.Parse(m.Groups[11].Value, CultureInfo.InvariantCulture)) * 60_000.0;
            ms += m.Groups[9].Value == "+" ? -off : off;
        }
        return ms;
    }

    public static RuleAction? ParseAction(object? v)
    {
        var o = Plain.Obj(v);
        if (o == null) return null;
        object? a = o.GetValueOrDefault("action");
        if (a is "drop") return RuleAction.Drop;
        if (a is "keep") return RuleAction.Keep;
        if (a is "code") return o.GetValueOrDefault("shape") is "alnum" ? RuleAction.CodeAlnum : RuleAction.Code;
        if (a is "graphql") return RuleAction.Graphql;
        if (a is "hmac") return new RuleAction { Kind = ActionKind.Hmac, Domain = Plain.Str(o.GetValueOrDefault("domain"), "id") };
        if (a is "bucket" && o.GetValueOrDefault("kind") is "num")
        {
            var bounds = new List<Bound>();
            foreach (object? x in Plain.Arr(o.GetValueOrDefault("bounds")))
            {
                string lex = x is Lex l ? l.Text : Convert.ToString(x, CultureInfo.InvariantCulture) ?? "0";
                bounds.Add(new Bound(JsonNumbers.Canonical(lex), double.Parse(lex, NumberStyles.Float, CultureInfo.InvariantCulture)));
            }
            return new RuleAction { Kind = ActionKind.Bucket, BucketKind = "num", Bounds = bounds };
        }
        if (a is "bucket" && o.GetValueOrDefault("kind") is "time")
            return new RuleAction { Kind = ActionKind.Bucket, BucketKind = "time", Unit = Plain.Str(o.GetValueOrDefault("unit"), "day") };
        return RuleAction.Drop;
    }

    private static Dictionary<string, RuleAction> NameMap(object? v)
    {
        var m = new Dictionary<string, RuleAction>(StringComparer.Ordinal);
        var o = Plain.Obj(v);
        if (o == null) return m;
        foreach (var kv in o)
        {
            var a = ParseAction(kv.Value);
            if (a != null) m[kv.Key] = a;
        }
        return m;
    }

    // ".@name" selects an XML attribute (v1.19, sanitizer.md 5.0 and 22.2).
    private static readonly Regex NameStep = new(@"\G@?[A-Za-z_][A-Za-z0-9_-]{0,63}", RegexOptions.CultureInvariant);

    /// <summary>Parses a tt-path; null if it does not follow the grammar.</summary>
    public static List<Step>? ParseTtPath(string p)
    {
        if (p.Length == 0 || p[0] != '$') return null;
        var steps = new List<Step>();
        int i = 1;
        while (i < p.Length)
        {
            if (string.CompareOrdinal(p, i, ".*", 0, 2) == 0)
            {
                steps.Add(new Step(StepKind.Any, null));
                i += 2;
            }
            else if (string.CompareOrdinal(p, i, "[*]", 0, 3) == 0)
            {
                steps.Add(new Step(StepKind.Idx, null));
                i += 3;
            }
            else if (string.CompareOrdinal(p, i, ".#text", 0, 6) == 0)
            {
                // the mixed text of an XML element (v1.19)
                steps.Add(new Step(StepKind.Name, "#text"));
                i += 6;
            }
            else if (p[i] == '.')
            {
                Match m = NameStep.Match(p, i + 1);
                if (!m.Success) return null;
                steps.Add(new Step(StepKind.Name, m.Value));
                i += 1 + m.Length;
            }
            else return null;
        }
        return steps;
    }

    public static Part? ParsePart(object? v)
    {
        var o = Plain.Obj(v);
        if (o == null) return null;
        var part = new Part
        {
            Query = NameMap(o.GetValueOrDefault("query")),
            Headers = NameMap(o.GetValueOrDefault("headers")),
            Cookies = NameMap(o.GetValueOrDefault("cookies")),
            PathParams = NameMap(o.GetValueOrDefault("path")),
        };
        foreach (object? r in Plain.Arr(o.GetValueOrDefault("body")))
        {
            var ro = Plain.Obj(r);
            if (ro == null) continue;
            string path = Plain.Str(ro.GetValueOrDefault("path"), "");
            var steps = ParseTtPath(path);
            var action = ParseAction(ro.GetValueOrDefault("action"));
            if (steps == null || action == null) continue;
            part.Body.Add(new BodyRule { Path = path, Steps = steps, Names = steps.Count(s => s.Kind == StepKind.Name), Action = action });
        }
        return part;
    }

    public static Op? ParseOpKey(string key)
    {
        int sp = key.IndexOf(' ');
        if (sp <= 0) return null;
        string method = key.Substring(0, sp);
        string tmpl = key.Substring(sp + 1);
        if (tmpl.Length == 0 || tmpl[0] != '/') return null;
        var segs = new List<TemplateSeg>();
        int literals = 0;
        foreach (string s in tmpl.Split('/'))
        {
            if (s.Length == 0) continue;
            if (s[0] == '{' && s[s.Length - 1] == '}') segs.Add(new TemplateSeg(null, s.Substring(1, s.Length - 2)));
            else
            {
                segs.Add(new TemplateSeg(s, null));
                literals++;
            }
        }
        return new Op { Key = key, Method = method, Segs = segs, Literals = literals };
    }

    private static readonly Regex BaseRe = Re.Full("([a-z][a-z0-9+.-]*://[^/]*)(/.*)?");

    /// <summary>Splits a normalized <c>match.base</c> into origin and path segments.</summary>
    public static (string Origin, List<string> Segs) SplitBase(string b)
    {
        Match m = BaseRe.Match(b);
        if (!m.Success) return (b, new List<string>());
        var segs = (m.Groups[2].Success ? m.Groups[2].Value : "").Split('/').Where(s => s.Length > 0).ToList();
        return (m.Groups[1].Value, segs);
    }
}

/// <summary>Body checks (policy.md 4, schema policy-compiled.v1), signed envelope verification (policy.md 3) and HMAC key parsing (sanitizer.md 7.1).</summary>
internal static class PolicyChecks
{
    public static readonly HashSet<string> ReservedDomains = new(StringComparer.Ordinal) { "subject", "sample", "sample-trace", "discovery" };
    public const string BodyFormat = "tt.policy.body/v1";
    public const string EnvelopeFormat = "tt.policy.compiled/v1";
    public static readonly byte[] SignaturePrefix = Encoding.Latin1.GetBytes("tt.policy.body/v1\0");

    // --- every action of a body ---

    private static IEnumerable<Dictionary<string, object?>> ActionsOf(Dictionary<string, object?> body)
    {
        var all = new List<Dictionary<string, object?>>();
        void Parts(object? scope, string[] keys)
        {
            var s = Plain.Obj(scope);
            if (s == null) return;
            foreach (string k in keys)
            {
                var p = Plain.Obj(s.GetValueOrDefault(k));
                if (p != null) all.Add(p);
            }
        }
        Parts(body.GetValueOrDefault("global"), new[] { "request", "response", "errors" });
        foreach (object? svc in Plain.Arr(body.GetValueOrDefault("services")))
        {
            Parts(svc, new[] { "request", "response", "errors" });
            foreach (object? op in Plain.Arr(Plain.Obj(svc)?.GetValueOrDefault("ops"))) Parts(op, new[] { "request", "response" });
        }
        foreach (var p in all)
        {
            foreach (string sec in new[] { "query", "headers", "cookies", "path" })
            {
                var m = Plain.Obj(p.GetValueOrDefault(sec));
                if (m == null) continue;
                foreach (var kv in m)
                {
                    var a = Plain.Obj(kv.Value);
                    if (a != null) yield return a;
                }
            }
            foreach (object? r in Plain.Arr(p.GetValueOrDefault("body")))
            {
                var a = Plain.Obj(Plain.Obj(r)?.GetValueOrDefault("action"));
                if (a != null) yield return a;
            }
        }
    }

    /// <summary>Detail prefix of a refusal raised by the v1.3 safety subset; the agent reports it as <c>policy_unsafe</c>.</summary>
    public const string UnsafeDetail = "unsafe";

    private static readonly HashSet<string> CredentialHeaders = new(StringComparer.Ordinal) { "authorization", "cookie", "set-cookie", "proxy-authorization" };

    private static RefusedException Unsafe(string why) => new("policy_rejected", UnsafeDetail + ": " + why);

    /// <summary>
    /// Source-side safety subset (hardening.md 2.1, v1.3), applied to every signed body:
    /// H1 keep, code (v1.11) or hmac on authorization, cookie, set-cookie, proxy-authorization (header rules of request, response
    /// and errors; global, services and operations); H2 keep, code or hmac on a tt-path with any wildcard step (<c>.*</c> or <c>[*]</c>) in the global
    /// body rules; H3 discovery or auto_words expiring later than created_at + 7 days.
    /// Properties of the body: neither the clock nor the group matter.
    /// </summary>
    public static void CheckUnsafe(Dictionary<string, object?> b)
    {
        var parts = new List<Dictionary<string, object?>>();
        void Collect(object? scope, string[] keys)
        {
            var s = Plain.Obj(scope);
            if (s == null) return;
            foreach (string k in keys)
            {
                var p = Plain.Obj(s.GetValueOrDefault(k));
                if (p != null) parts.Add(p);
            }
        }
        var g = Plain.Obj(b.GetValueOrDefault("global"));
        Collect(g, new[] { "request", "response", "errors" });
        foreach (object? svc in Plain.Arr(b.GetValueOrDefault("services")))
        {
            Collect(svc, new[] { "request", "response", "errors" });
            foreach (object? op in Plain.Arr(Plain.Obj(svc)?.GetValueOrDefault("ops"))) Collect(op, new[] { "request", "response" });
        }
        foreach (var p in parts)
        {
            var headers = Plain.Obj(p.GetValueOrDefault("headers"));
            if (headers == null) continue;
            foreach (var kv in headers)
            {
                object? act = Plain.Obj(kv.Value)?.GetValueOrDefault("action");
                if (CredentialHeaders.Contains(kv.Key) && act is "keep" or "code" or "hmac")
                    throw Unsafe(act + " on header " + kv.Key);
            }
        }
        if (g != null)
        {
            foreach (string k in new[] { "request", "response", "errors" })
            {
                foreach (object? r in Plain.Arr(Plain.Obj(g.GetValueOrDefault(k))?.GetValueOrDefault("body")))
                {
                    var ro = Plain.Obj(r);
                    object? act = Plain.Obj(ro?.GetValueOrDefault("action"))?.GetValueOrDefault("action");
                    if (act is "keep" or "code" or "hmac" && ro?.GetValueOrDefault("path") is string path && (path.Contains(".*", StringComparison.Ordinal) || path.Contains("[*]", StringComparison.Ordinal)))
                        throw Unsafe(act + " on " + path + " in a global rule");
                }
            }
        }
        double limit = Parsing.ParseTime(b.GetValueOrDefault("created_at")) + 7 * 86_400_000d;
        var seg = Plain.Obj(b.GetValueOrDefault("segments"));
        if (seg != null && seg.GetValueOrDefault("auto_words") is true && Parsing.ParseTime(seg.GetValueOrDefault("auto_words_expires_at")) > limit)
            throw Unsafe("auto_words expires beyond created_at + 7 days");
        var d = Plain.Obj(b.GetValueOrDefault("discovery"));
        if (d != null && d.GetValueOrDefault("enabled") is true && Parsing.ParseTime(d.GetValueOrDefault("expires_at")) > limit)
            throw Unsafe("discovery expires beyond created_at + 7 days");
    }

    /// <summary>Minimal body checks of the conformance runner (format.md, step 1), plus the v1.3 safety subset.</summary>
    public static Dictionary<string, object?> CheckBodyMinimal(object? body)
    {
        var b = Plain.Obj(body);
        if (b == null || !(b.GetValueOrDefault("format") is BodyFormat)) throw new RefusedException("policy_rejected", "body format");
        foreach (var a in ActionsOf(b))
        {
            if (a.GetValueOrDefault("action") is "hmac" && a.GetValueOrDefault("domain") is string d && ReservedDomains.Contains(d))
                throw new RefusedException("policy_rejected", "reserved domain");
        }
        CheckUnsafe(b);
        return b;
    }

    // --- full schema validation (schemas/policy-compiled.v1.schema.json#/$defs/body) ---

    private sealed class SchemaError : Exception
    {
        public SchemaError(string m) : base(m) { }
    }

    private delegate void V(object? v, string at);

    private static void Fail(string at, string why) => throw new SchemaError(at + ": " + why);

    private static V VStr(Regex re) => (v, at) =>
    {
        if (v is not string s || !re.IsMatch(s)) Fail(at, "string");
    };

    private static V VInt(double min, double max = 9007199254740991) => (v, at) =>
    {
        if (v is not Lex l || !JsonNumbers.IsIntLexeme(l.Text)) { Fail(at, "integer"); return; }
        double n = l.ToDouble();
        if (n < min || n > max) Fail(at, "range");
    };

    private static readonly V VBool = (v, at) =>
    {
        if (v is not bool) Fail(at, "boolean");
    };

    private static readonly V VTime = (v, at) =>
    {
        if (double.IsNaN(Parsing.ParseTime(v))) Fail(at, "date-time");
    };

    private static V VConst(object c) => (v, at) =>
    {
        if (!Equals(v, c)) Fail(at, "const");
    };

    private static readonly V Any = (_, _) => { };

    private static string UniqueKey(object? x) => x is Lex l ? "n:" + l.Text : x is string s ? "s:" + s : "o:" + x;

    private static V VArr(V item, int max, bool unique, int min = 0) => (v, at) =>
    {
        if (v is not List<object?> list || list.Count > max || list.Count < min) { Fail(at, "array"); return; }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < list.Count; i++)
        {
            item(list[i], at + "[" + i + "]");
            if (unique && !seen.Add(UniqueKey(list[i]))) Fail(at, "unique");
        }
    };

    private static V VObj(Dictionary<string, V> props, params string[] required) => (v, at) =>
    {
        if (v is not Dictionary<string, object?> o) { Fail(at, "object"); return; }
        foreach (var kv in o)
        {
            if (!props.TryGetValue(kv.Key, out V? p)) Fail(at + "." + kv.Key, "unexpected");
            else p(kv.Value, at + "." + kv.Key);
        }
        foreach (string r in required)
        {
            if (!o.ContainsKey(r)) Fail(at + "." + r, "required");
        }
    };

    private static V VMap(Regex name, V val, int max) => (v, at) =>
    {
        if (v is not Dictionary<string, object?> o) { Fail(at, "object"); return; }
        if (o.Count > max) Fail(at, "maxProperties");
        foreach (var kv in o)
        {
            if (!name.IsMatch(kv.Key)) Fail(at + "." + kv.Key, "name");
            val(kv.Value, at + "." + kv.Key);
        }
    };

    private static readonly Regex RePolicyId = Re.Full("[a-z0-9][a-z0-9-]{0,62}");
    private static readonly Regex ReDomain = Re.Full("[a-z][a-z0-9_-]{0,31}");
    private static readonly Regex ReKid = Re.Full("[a-z0-9]{1,8}");
    private static readonly Regex ReHostPort = Re.Full("[a-z0-9.-]{1,253}(:[0-9]{1,5})?");
    private static readonly Regex ReKeyName = Re.Full("[A-Za-z_][A-Za-z0-9_.-]{0,63}");
    private static readonly Regex ReHeaderName = Re.Full("[a-z0-9!#$%&'*+.^_`|~-]{1,64}");
    private static readonly Regex ReParamName = Re.Full("[A-Za-z_][A-Za-z0-9_]{0,63}");
    private static readonly Regex ReTtPath = Re.Full("\\$(\\.@?[A-Za-z_][A-Za-z0-9_-]{0,63}|\\.#text|\\.\\*|\\[\\*\\]){0,64}");
    private static readonly Regex ReOpKey = Re.Full("[A-Z]{1,16} /([A-Za-z0-9._~-]{1,64}|\\{[A-Za-z_][A-Za-z0-9_]{0,63}\\})?(/([A-Za-z0-9._~-]{1,64}|\\{[A-Za-z_][A-Za-z0-9_]{0,63}\\})){0,31}");
    private static readonly Regex ReBase = Re.Full("https?://[a-z0-9.-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~-]{1,64})*");
    private static readonly Regex ReServiceName = Re.Full("[a-z0-9][a-z0-9._-]{0,62}");
    private static readonly Regex ReEpoch = Re.Full("[A-Za-z0-9._-]{1,32}");
    private static readonly Regex ReUnit = Re.Full("(year|month|day|hour)");
    private static readonly Regex ReSubjectName = Re.Full("[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}");
    private static readonly Regex ReAllow = Re.Full("[A-Za-z0-9._~-]{1,64}");
    private static readonly Regex ReFromKind = Re.Full("(header|cookie)");
    private static readonly Regex ReHostsDiscovery = Re.Full("(auto|off)");

    private static V VAction() => (v, at) =>
    {
        if (v is not Dictionary<string, object?> o) { Fail(at, "action"); return; }
        object? a = o.GetValueOrDefault("action");
        // v1.19: code may carry the shape alnum (sanitizer.md 5.6); no other shape and no shape on other actions.
        if (a is "code" && o.ContainsKey("shape")) { VObj(new() { ["action"] = Any, ["shape"] = VConst("alnum") }, "action", "shape")(v, at); return; }
        if (a is "drop" or "keep" or "code" or "graphql") { VObj(new() { ["action"] = Any }, "action")(v, at); return; }
        if (a is "hmac")
        {
            VObj(new() { ["action"] = Any, ["domain"] = VStr(ReDomain) }, "action", "domain")(v, at);
            if (o.GetValueOrDefault("domain") is string d && ReservedDomains.Contains(d)) Fail(at, "reserved domain");
            return;
        }
        if (a is "bucket" && o.GetValueOrDefault("kind") is "num")
        {
            VObj(new()
            {
                ["action"] = Any,
                ["kind"] = Any,
                ["bounds"] = VArr((x, a2) =>
                {
                    if (x is not Lex lx) Fail(a2, "number");
                    else if (lx.Text.Length > 64) Fail(a2, "lexeme");
                }, 32, false, 1),
            }, "action", "kind", "bounds")(v, at);
            var ds = ((List<object?>)o["bounds"]!).Select(x => ((Lex)x!).ToDouble()).ToList();
            for (int i = 1; i < ds.Count; i++)
            {
                if (!(ds[i - 1] < ds[i])) Fail(at, "bounds not increasing");
            }
            return;
        }
        if (a is "bucket" && o.GetValueOrDefault("kind") is "time")
        {
            VObj(new() { ["action"] = Any, ["kind"] = Any, ["unit"] = VStr(ReUnit) }, "action", "kind", "unit")(v, at);
            return;
        }
        Fail(at, "action");
    };

    private static readonly V Action = VAction();
    private static readonly V BodyRules = VArr(VObj(new() { ["path"] = VStr(ReTtPath), ["action"] = Action }, "path", "action"), 1024, false);
    private static readonly V VPart = VObj(new()
    {
        ["query"] = VMap(ReKeyName, Action, 256),
        ["headers"] = VMap(ReHeaderName, Action, 256),
        ["cookies"] = VMap(ReKeyName, Action, 256),
        ["body"] = BodyRules,
    });
    private static readonly V VOpPart = VObj(new()
    {
        ["path"] = VMap(ReParamName, Action, 32),
        ["query"] = VMap(ReKeyName, Action, 256),
        ["headers"] = VMap(ReHeaderName, Action, 256),
        ["cookies"] = VMap(ReKeyName, Action, 256),
        ["body"] = BodyRules,
    });
    private static readonly V VScope = VObj(new() { ["request"] = VPart, ["response"] = VPart, ["errors"] = VPart });
    private static readonly V VMatch = (v, at) =>
    {
        if (v is not Dictionary<string, object?> o) { Fail(at, "match"); return; }
        if (o.ContainsKey("base")) { VObj(new() { ["base"] = VStr(ReBase) }, "base")(v, at); return; }
        VObj(new() { ["inbound"] = VConst(true), ["internal"] = VBool }, "inbound", "internal")(v, at);
    };
    private static readonly V VService = VObj(new()
    {
        ["name"] = VStr(ReServiceName),
        ["match"] = VMatch,
        ["request"] = VPart,
        ["response"] = VPart,
        ["errors"] = VPart,
        ["ops"] = VArr(VObj(new() { ["op"] = VStr(ReOpKey), ["request"] = VOpPart, ["response"] = VOpPart }, "op"), 4096, false),
    }, "name", "match", "ops");

    private static readonly Regex ReJsonPath = Re.Full("[A-Za-z0-9_-]{1,64}(\\.[A-Za-z0-9_-]{1,64}){0,7}");

    // identity.subject; spec v1.18: json_path reads a header only and excludes jwt_claim.
    private static readonly V VSubjectShape = VObj(new()
    {
        ["from"] = VStr(ReFromKind),
        ["name"] = VStr(ReSubjectName),
        ["jwt_claim"] = VStr(ReKeyName),
        ["json_path"] = VStr(ReJsonPath),
    }, "from", "name");

    private static readonly V VSubject = (v, at) =>
    {
        VSubjectShape(v, at);
        if (v is Dictionary<string, object?> o && o.ContainsKey("json_path") && (o.ContainsKey("jwt_claim") || !(o.GetValueOrDefault("from") is string f && f == "header")))
            Fail(at + ".json_path", "header only, excludes jwt_claim");
    };

    private static readonly V VBody = VObj(new()
    {
        ["format"] = VConst(BodyFormat),
        ["policy_id"] = VStr(RePolicyId),
        ["version"] = VInt(1),
        ["issued_seq"] = VInt(1),
        ["created_at"] = VTime,
        ["not_after"] = VTime,
        ["targets"] = VObj(new() { ["groups"] = VArr(VStr(RePolicyId), 256, true, 1) }, "groups"),
        ["hmac"] = VObj(new() { ["kid"] = VStr(ReKid), ["accept_kids"] = VArr(VStr(ReKid), 4, true), ["epoch"] = VStr(ReEpoch) }, "kid", "epoch", "accept_kids"),
        ["identity"] = VObj(new()
        {
            ["subject"] = VSubject,
        }),
        ["sampling"] = VObj(new() { ["rate_bp"] = VInt(0, 10000), ["trust_baggage"] = VBool, ["propagate_to"] = VArr(VStr(ReHostPort), 256, true) }, "rate_bp", "trust_baggage", "propagate_to"),
        ["segments"] = (v, at) =>
        {
            VObj(new()
            {
                ["auto_words"] = VBool,
                ["auto_words_expires_at"] = VTime,
                ["allow"] = VArr(VStr(ReAllow), 1024, true),
                ["hosts_allow"] = VArr(VStr(ReHostPort), 1024, true),
            }, "auto_words", "allow", "hosts_allow")(v, at);
            if (v is Dictionary<string, object?> so && so.GetValueOrDefault("auto_words") is true && !so.ContainsKey("auto_words_expires_at"))
                Fail(at, "auto_words_expires_at required");
        },
        ["limits"] = VObj(new()
        {
            ["max_body_bytes"] = VInt(0, 16777216),
            ["max_depth"] = VInt(1, 128),
            ["max_array"] = VInt(0, 1024),
            ["max_keys"] = VInt(1, 4096),
            ["keep_max_bytes"] = VInt(0, 1024),
        }, "max_body_bytes", "max_depth", "max_array", "max_keys", "keep_max_bytes"),
        ["bodies"] = VObj(new()
        {
            ["xml"] = VBool,
            ["multipart"] = VBool,
            ["docs"] = VBool,
            ["max_large_body_bytes"] = VInt(0, 67108864),
            ["large_array"] = VInt(0, 1024),
            ["large_nested_array"] = VInt(0, 1024),
        }, "xml", "multipart", "docs", "max_large_body_bytes", "large_array", "large_nested_array"),
        ["discovery"] = VObj(new() { ["enabled"] = VBool, ["expires_at"] = VTime }, "enabled", "expires_at"),
        ["hosts"] = VObj(new() { ["discovery"] = VStr(ReHostsDiscovery) }, "discovery"),
        ["global"] = VScope,
        ["services"] = VArr(VService, 1024, false),
    }, "format", "policy_id", "version", "issued_seq", "created_at", "not_after", "targets", "hmac", "sampling", "segments", "limits", "global", "services");

    /// <summary>Full schema validation of a policy body, plus reserved domains, double bounds and the v1.3 safety subset.</summary>
    public static Dictionary<string, object?> ValidateBodySchema(object? body)
    {
        try
        {
            VBody(body, "$");
        }
        catch (SchemaError e)
        {
            throw new RefusedException("policy_rejected", "schema " + e.Message);
        }
        var plain = (Dictionary<string, object?>)body!;
        CheckUnsafe(plain);
        return plain;
    }

    // --- envelope ---

    /// <summary>Strict base64url without padding.</summary>
    public static byte[]? B64UrlDecodeStrict(string s) => Utf8Util.B64UrlDecodeStrict(s);

    /// <summary>Raw 32-byte Ed25519 key from its base64url form; null if malformed.</summary>
    public static byte[]? Ed25519PublicKey(string rawB64Url)
    {
        byte[]? raw = Utf8Util.B64UrlDecodeStrict(rawB64Url);
        return raw is { Length: 32 } ? raw : null;
    }

    internal sealed record VerifiedPolicy(byte[] BodyBytes, Dictionary<string, object?> Body, string Hash);

    private static bool SameNum(object? a, object? b) => a is Lex x && b is Lex y ? x.Text == y.Text : Equals(a, b);

    /// <summary>
    /// Verifies a <c>tt.policy.compiled/v1</c> envelope (policy.md 3-4 conditions 1-2). <paramref name="keys"/> maps a pinned,
    /// non-revoked signature kid to its raw public key. <paramref name="strict"/> applies the full body schema.
    /// </summary>
    public static VerifiedPolicy VerifyEnvelope(object? env, IReadOnlyDictionary<string, byte[]> keys, bool strict)
    {
        static Exception Reject(string why) => new RefusedException("policy_rejected", why);
        var e = Plain.Obj(env) ?? throw Reject("envelope");
        if (strict)
        {
            var allowed = new HashSet<string> { "format", "policy_id", "version", "issued_seq", "hash", "body_b64", "signature" };
            foreach (string k in e.Keys)
            {
                if (!allowed.Contains(k)) throw Reject("envelope field");
            }
        }
        if (!(e.GetValueOrDefault("format") is EnvelopeFormat)) throw Reject("envelope format");
        var sig = Plain.Obj(e.GetValueOrDefault("signature"));
        if (sig == null || !(sig.GetValueOrDefault("alg") is "Ed25519") || sig.GetValueOrDefault("kid") is not string kid || sig.GetValueOrDefault("sig") is not string sigStr)
            throw Reject("signature");
        if (!keys.TryGetValue(kid, out byte[]? pub)) throw Reject("unknown kid");
        if (e.GetValueOrDefault("body_b64") is not string bodyB64) throw Reject("body_b64");
        byte[]? bodyBytes = Utf8Util.B64UrlDecodeStrict(bodyB64);
        if (bodyBytes == null || bodyBytes.Length == 0) throw Reject("body_b64");
        string hash = "sha256:" + Utf8Util.HexLower(SHA256.HashData(bodyBytes));
        if (!(e.GetValueOrDefault("hash") is string hs && hs == hash)) throw Reject("hash");
        byte[]? sigBytes = Utf8Util.B64UrlDecodeStrict(sigStr);
        if (sigBytes == null || sigBytes.Length != 64) throw Reject("signature encoding");
        var msg = new byte[SignaturePrefix.Length + bodyBytes.Length];
        SignaturePrefix.CopyTo(msg, 0);
        bodyBytes.CopyTo(msg, SignaturePrefix.Length);
        bool ok;
        try { ok = Ed25519.Verify(pub, msg, sigBytes); }
        catch (Exception) { ok = false; }
        if (!ok) throw Reject("signature");
        object? plain;
        try { plain = Plain.From(JsonParser.Parse(bodyBytes), true); }
        catch (JsonException2) { throw Reject("body json"); }
        var body = strict ? ValidateBodySchema(plain) : CheckBodyMinimal(plain);
        if (!SameNum(e.GetValueOrDefault("policy_id"), body.GetValueOrDefault("policy_id"))) throw Reject("policy_id mismatch");
        if (!SameNum(e.GetValueOrDefault("version"), body.GetValueOrDefault("version"))) throw Reject("version mismatch");
        if ((strict || e.ContainsKey("issued_seq") || body.ContainsKey("issued_seq")) && !SameNum(e.GetValueOrDefault("issued_seq"), body.GetValueOrDefault("issued_seq")))
            throw Reject("issued_seq mismatch");
        if (strict && !(body.GetValueOrDefault("format") is BodyFormat)) throw Reject("body format");
        CheckBodyMinimal(body);
        return new VerifiedPolicy(bodyBytes, body, hash);
    }

    /// <summary>
    /// policy.md 4, conditions 3-5: group, expiry, issued_seq ordering. <paramref name="allowEqualSeq"/> lets a source re-verify the
    /// very policy it already accepted (cache at start-up).
    /// </summary>
    public static void CheckAcceptance(Policy p, string group, double now, long lastIssuedSeq, long minIssuedSeq, bool allowEqualSeq = false)
    {
        if (!p.Groups.Contains(group)) throw new RefusedException("policy_rejected", "group");
        if (!(now < p.NotAfter)) throw new RefusedException("expired_policy");
        bool fresh = allowEqualSeq ? p.IssuedSeq >= lastIssuedSeq : p.IssuedSeq > lastIssuedSeq;
        if (!fresh) throw new RefusedException("policy_rejected", "issued_seq replay");
        if (p.IssuedSeq < minIssuedSeq) throw new RefusedException("policy_rejected", "issued_seq below minimum");
    }

    // --- HMAC key (7.1) ---

    internal sealed class KeyRing
    {
        public readonly Dictionary<string, byte[]> Keys = new(StringComparer.Ordinal);
        public readonly List<string> Order = new();
    }

    private static readonly Regex ReKidOnly = Re.Full("[a-z0-9]{1,8}");

    /// <summary>Parses the content of TT_HMAC_KEY / TT_HMAC_KEY_FILE. Throws <see cref="RefusedException"/> with <c>key_missing</c>.</summary>
    public static KeyRing ParseKeyRing(string? text)
    {
        if (text == null) throw new RefusedException("key_missing", "absent");
        var ring = new KeyRing();
        foreach (string raw in text.Split('\n'))
        {
            string line = raw.EndsWith('\r') ? raw.Substring(0, raw.Length - 1) : raw;
            if (line.Length == 0) continue;
            int c = line.IndexOf(':');
            if (c < 0) throw new RefusedException("key_missing", "malformed");
            string kid = line.Substring(0, c);
            if (!ReKidOnly.IsMatch(kid)) throw new RefusedException("key_missing", "kid");
            byte[]? key = Utf8Util.B64UrlDecodeStrict(line.Substring(c + 1));
            if (key == null || key.Length < 32) throw new RefusedException("key_missing", "key bytes");
            if (!ring.Keys.ContainsKey(kid))
            {
                ring.Keys[kid] = key;
                ring.Order.Add(kid);
            }
        }
        if (ring.Keys.Count == 0) throw new RefusedException("key_missing", "empty");
        return ring;
    }

    /// <summary>7.1: picks the key for a policy (hmac.kid, then accept_kids in order).</summary>
    public static (string Kid, byte[] Key) SelectKey(KeyRing ring, Policy policy)
    {
        if (ring.Keys.TryGetValue(policy.Kid, out byte[]? k)) return (policy.Kid, k);
        foreach (string kid in policy.AcceptKids)
        {
            if (ring.Keys.TryGetValue(kid, out byte[]? a)) return (kid, a);
        }
        throw new RefusedException("key_mismatch");
    }
}
