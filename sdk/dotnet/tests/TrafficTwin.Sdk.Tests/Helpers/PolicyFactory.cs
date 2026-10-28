using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using TrafficTwin.Sdk.Sanitizing;

namespace TrafficTwin.Sdk.Tests.Helpers;

/// <summary>Builds compiled policy bodies and signed envelopes (invented e-commerce data).</summary>
internal static class PolicyFactory
{
    public const string SigningKid = "policy-test-1";
    public const string HmacKeyLine = "k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    public static CNum N(long v) => new(v.ToString(CultureInfo.InvariantCulture));

    public static Dictionary<string, object?> Map(params (string, object?)[] kv)
    {
        var d = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var (k, v) in kv) d[k] = v;
        return d;
    }

    public static List<object?> List(params object?[] items) => new(items);

    public static Dictionary<string, object?> Keep() => Map(("action", "keep"));
    public static Dictionary<string, object?> Drop() => Map(("action", "drop"));
    public static Dictionary<string, object?> Hmac(string domain) => Map(("action", "hmac"), ("domain", domain));
    public static Dictionary<string, object?> BucketNum(params long[] bounds) =>
        Map(("action", "bucket"), ("kind", "num"), ("bounds", new List<object?>(Array.ConvertAll(bounds, b => (object?)N(b)))));

    public static Dictionary<string, object?> Rule(string path, Dictionary<string, object?> action) => Map(("path", path), ("action", action));

    public static string Iso(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// <summary>The policy used by the integration tests: shop-api (inbound) and a carrier base URL (outbound).</summary>
    public static Dictionary<string, object?> Shop(string? carrierBase = null, long issuedSeq = 1, long rateBp = 10000, string group = "shop",
        bool trustBaggage = false, bool internalService = false, string[]? propagateTo = null, DateTimeOffset? notAfter = null, long maxBodyBytes = 1048576)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var services = new List<object?>
        {
            Map(
                ("name", "shop-api"),
                ("match", Map(("inbound", true), ("internal", internalService))),
                ("ops", List(
                    Map(("op", "POST /orders"),
                        ("request", Map(("body", List(Rule("$.items[*].qty", BucketNum(0, 2, 5)))))),
                        ("response", Map(("body", List(Rule("$.id", Hmac("order")), Rule("$.status", Keep())))))),
                    Map(("op", "GET /orders/{id}"),
                        ("request", Map(("path", Map(("id", Hmac("order"))))))),
                    Map(("op", "GET /health"))))),
        };
        if (carrierBase != null)
        {
            services.Add(Map(
                ("name", "shipping-ext"),
                ("match", Map(("base", carrierBase))),
                ("ops", List(
                    Map(("op", "POST /v1/shipments"),
                        ("request", Map(("body", List(Rule("$.orderId", Hmac("order")))))),
                        ("response", Map(("body", List(Rule("$.shipmentId", Hmac("shipment")), Rule("$.status", Keep())))))))),
                ("errors", Map(("body", List(Rule("$.error.code", Keep())))))));
        }
        return Map(
            ("format", "tt.policy.body/v1"),
            ("policy_id", "p-shop"),
            ("version", N(1)),
            ("issued_seq", N(issuedSeq)),
            ("created_at", Iso(now.AddMinutes(-1))),
            ("not_after", Iso(notAfter ?? now.AddDays(30))),
            ("targets", Map(("groups", List(group)))),
            ("hmac", Map(("kid", "k1"), ("accept_kids", List()), ("epoch", "2026-10"))),
            ("identity", Map(("subject", Map(("from", "header"), ("name", "x-customer"))))),
            ("sampling", Map(("rate_bp", N(rateBp)), ("trust_baggage", trustBaggage), ("propagate_to", new List<object?>(Array.ConvertAll(propagateTo ?? Array.Empty<string>(), s => (object?)s))))),
            ("segments", Map(("auto_words", false), ("allow", List("v1")), ("hosts_allow", List()))),
            ("limits", Map(("max_body_bytes", N(maxBodyBytes)), ("max_depth", N(32)), ("max_array", N(32)), ("max_keys", N(256)), ("keep_max_bytes", N(64)))),
            ("discovery", Map(("enabled", false), ("expires_at", Iso(now.AddDays(1))))),
            ("global", Map(
                ("request", Map(("headers", Map(("content-type", Keep()))))),
                ("response", Map(("headers", Map(("content-type", Keep()))))))),
            ("services", services));
    }

    public static byte[] BodyBytes(Dictionary<string, object?> body) => Encoding.UTF8.GetBytes(Canonical.Write(body));

    /// <summary>A signed <c>tt.policy.compiled/v1</c> envelope as JSON text.</summary>
    public static string Envelope(Dictionary<string, object?> body, byte[] seed, string kid = SigningKid)
    {
        byte[] bytes = BodyBytes(body);
        byte[] prefix = Encoding.Latin1.GetBytes("tt.policy.body/v1\0");
        var msg = new byte[prefix.Length + bytes.Length];
        prefix.CopyTo(msg, 0);
        bytes.CopyTo(msg, prefix.Length);
        byte[] sig = TestEd25519.Sign(seed, msg);
        var env = Map(
            ("format", "tt.policy.compiled/v1"),
            ("policy_id", body["policy_id"]),
            ("version", body["version"]),
            ("issued_seq", body["issued_seq"]),
            ("hash", "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()),
            ("body_b64", Utf8Util.B64UrlNoPad(bytes)),
            ("signature", Map(("alg", "Ed25519"), ("kid", kid), ("sig", Utf8Util.B64UrlNoPad(sig)))));
        return Canonical.Write(env);
    }
}
