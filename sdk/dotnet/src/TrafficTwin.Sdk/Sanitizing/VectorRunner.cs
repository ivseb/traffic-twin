using System;
using System.Collections.Generic;
using System.IO;

namespace TrafficTwin.Sdk.Sanitizing;

/// <summary>Result of one conformance vector (conformance/format.md).</summary>
internal sealed record VectorResult(string Outcome, string? Canonical = null, string? SampledBy = null, string? Code = null);

/// <summary>
/// Executes one conformance vector (conformance/format.md, "Executing a vector"). This is the test function every
/// source must expose (sanitizer.md 16).
/// </summary>
internal static class VectorRunner
{
    private static byte[] DecodeBytes(object? v)
    {
        if (v == null) return Array.Empty<byte>();
        if (v is string s) return Utf8Util.Utf8(s);
        if (v is Dictionary<string, object?> o && o.GetValueOrDefault("b64") is string b64) return Convert.FromBase64String(b64);
        throw new InvalidOperationException("bad bytes value");
    }

    private static long? Num(object? v) => v is Lex l ? (long)l.ToDouble() : null;

    private static List<(string, byte[])> Headers(object? v)
    {
        var res = new List<(string, byte[])>();
        foreach (object? pair in Plain.Arr(v))
        {
            var p = (List<object?>)pair!;
            res.Add(((string)p[0]!, DecodeBytes(p[1])));
        }
        return res;
    }

    private static long? Total(object? v) => v is "unknown" ? Exchange.UnknownTotal : Num(v);

    private static bool? Bool(object? v) => v as bool?;

    public static Exchange ToExchange(Dictionary<string, object?> inp)
    {
        var ex = new Exchange
        {
            Inbound = inp.GetValueOrDefault("dir") is "inbound",
            Method = Plain.Str(inp.GetValueOrDefault("method"), ""),
            RawPath = DecodeBytes(inp.GetValueOrDefault("raw_path")),
            RawQuery = inp.ContainsKey("raw_query") ? DecodeBytes(inp["raw_query"]) : null,
            ReqHeaders = Headers(inp.GetValueOrDefault("req_headers")),
            ReqBody = DecodeBytes(inp.GetValueOrDefault("req_body")),
            ReqBodyTotal = Total(inp.GetValueOrDefault("req_body_total")),
            ReqBodyConsumed = Bool(inp.GetValueOrDefault("req_body_consumed")),
            ReqBodyDecoded = Bool(inp.GetValueOrDefault("req_body_decoded")),
            RespHeaders = Headers(inp.GetValueOrDefault("resp_headers")),
            RespBody = DecodeBytes(inp.GetValueOrDefault("resp_body")),
            RespBodyTotal = Total(inp.GetValueOrDefault("resp_body_total")),
            RespBodyConsumed = Bool(inp.GetValueOrDefault("resp_body_consumed")),
            RespBodyDecoded = Bool(inp.GetValueOrDefault("resp_body_decoded")),
        };
        if (inp.GetValueOrDefault("service_name") is string sn) ex.ServiceName = sn;
        if (inp.GetValueOrDefault("url_base") is string ub) ex.UrlBase = ub;
        if (inp.GetValueOrDefault("framework_route") is string fr) ex.FrameworkRoute = fr;
        if (inp.GetValueOrDefault("framework") is string fw) ex.Framework = fw;
        if (inp.GetValueOrDefault("trace_id") is string ti) ex.TraceId = ti;
        if (inp.GetValueOrDefault("inherited") is bool inh) ex.Inherited = inh;
        long? st = Num(inp.GetValueOrDefault("status"));
        if (st.HasValue) ex.Status = (int)st.Value;
        if (inp.GetValueOrDefault("net_error") is string ne) ex.NetError = ne;
        return ex;
    }

    /// <summary>Parses a vector file with the lexeme-preserving parser.</summary>
    public static Dictionary<string, object?> Parse(byte[] bytes) =>
        (Dictionary<string, object?>)Plain.From(JsonParser.Parse(bytes), false)!;

    /// <summary>Runs one parsed vector. <paramref name="root"/> is the conformance/ directory (for policy_ref).</summary>
    public static VectorResult Run(Dictionary<string, object?> vec, string root)
    {
        double now = vec.GetValueOrDefault("now") is string ns ? Parsing.ParseTime(ns) : double.NaN;
        Sanitizer sanitizer;
        try
        {
            Dictionary<string, object?> body;
            if (vec.ContainsKey("policy_envelope"))
            {
                var keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
                var fk = Plain.Obj(vec.GetValueOrDefault("fleet_keys"));
                if (fk != null)
                {
                    foreach (var kv in fk)
                    {
                        byte[]? k = kv.Value is string raw ? PolicyChecks.Ed25519PublicKey(raw) : null;
                        if (k != null) keys[kv.Key] = k;
                    }
                }
                body = PolicyChecks.VerifyEnvelope(vec["policy_envelope"], keys, true).Body;
            }
            else if (vec.GetValueOrDefault("policy_ref") is string pref)
            {
                body = PolicyChecks.ValidateBodySchema(Plain.From(JsonParser.Parse(File.ReadAllBytes(Path.Combine(root, pref))), true));
            }
            else if (vec.ContainsKey("policy"))
            {
                body = PolicyChecks.ValidateBodySchema(vec["policy"]);
            }
            else
            {
                throw new RefusedException("no_policy");
            }
            var policy = new Policy(body);
            PolicyChecks.CheckAcceptance(policy,
                vec.GetValueOrDefault("source_group") as string ?? "",
                double.IsNaN(now) ? double.NaN : now,
                Num(vec.GetValueOrDefault("last_issued_seq")) ?? 0,
                Num(vec.GetValueOrDefault("min_issued_seq")) ?? 0);
            var ring = PolicyChecks.ParseKeyRing(vec.GetValueOrDefault("hmac_key") as string);
            var (kid, key) = PolicyChecks.SelectKey(ring, policy);
            sanitizer = new Sanitizer(policy, kid, key);
        }
        catch (RefusedException e)
        {
            return new VectorResult("refused", Code: e.Code);
        }
        var input = Plain.Obj(vec["input"])!;
        SanitizeResult r = sanitizer.Run(ToExchange(input), now);
        if (r.Outcome == Outcome.NotSampled) return new VectorResult("not_sampled", SampledBy: r.SampledBy);
        if (r.Outcome == Outcome.TooLarge) return new VectorResult("refused", Code: "event_too_large");
        return new VectorResult("event", Canonical: r.Canonical);
    }
}
