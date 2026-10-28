using System;
using System.Globalization;
using System.Text;
using TrafficTwin.Sdk.Sanitizing;
using Xunit;

namespace TrafficTwin.Sdk.Tests;

/// <summary>v1.3 source-side safety subset (docs/spec/hardening.md 2.1): H1, H2, H3.</summary>
public class SafetySubsetTests
{
    private const string Created = "2026-10-20T08:00:00Z";
    private const string Seg = "{\"auto_words\":false,\"allow\":[],\"hosts_allow\":[]}";
    private const string SvcHead = "{\"name\":\"shop-api\",\"match\":{\"inbound\":true,\"internal\":false}";

    private static string Body(string global, string services, string segments, string discovery) =>
        "{\"format\":\"tt.policy.body/v1\",\"policy_id\":\"p-shop\",\"version\":1,\"issued_seq\":1," +
        "\"created_at\":\"" + Created + "\",\"not_after\":\"2026-11-19T08:00:00Z\"," +
        "\"targets\":{\"groups\":[\"shop\"]},\"hmac\":{\"kid\":\"k1\",\"accept_kids\":[],\"epoch\":\"2026-10\"}," +
        "\"sampling\":{\"rate_bp\":10000,\"trust_baggage\":false,\"propagate_to\":[]}," +
        "\"segments\":" + segments + "," +
        "\"limits\":{\"max_body_bytes\":1048576,\"max_depth\":32,\"max_array\":32,\"max_keys\":256,\"keep_max_bytes\":64}," +
        (discovery.Length == 0 ? "" : "\"discovery\":" + discovery + ",") +
        "\"global\":" + global + ",\"services\":" + services + "}";

    private static string Outcome(string json)
    {
        try
        {
            PolicyChecks.ValidateBodySchema(Plain.From(JsonParser.Parse(Encoding.UTF8.GetBytes(json)), true));
            return "accepted";
        }
        catch (RefusedException r)
        {
            return r.Detail.StartsWith(PolicyChecks.UnsafeDetail, StringComparison.Ordinal) ? "unsafe" : r.Code;
        }
    }

    [Fact]
    public void H1CredentialHeaders()
    {
        foreach (string h in new[] { "authorization", "cookie", "set-cookie", "proxy-authorization" })
        {
            foreach (string act in new[] { "{\"action\":\"keep\"}", "{\"action\":\"hmac\",\"domain\":\"tok\"}" })
            {
                string rule = "{\"headers\":{\"" + h + "\":" + act + "}}";
                string what = h + " " + act;
                Assert.Equal("unsafe", Outcome(Body("{\"request\":" + rule + "}", "[]", Seg, "")));
                Assert.Equal("unsafe", Outcome(Body("{\"response\":" + rule + "}", "[]", Seg, "")));
                Assert.Equal("unsafe", Outcome(Body("{\"errors\":" + rule + "}", "[]", Seg, "")));
                Assert.Equal("unsafe", Outcome(Body("{}", "[" + SvcHead + ",\"errors\":" + rule + ",\"ops\":[]}]", Seg, "")));
                Assert.Equal("unsafe", Outcome(Body("{}", "[" + SvcHead + ",\"ops\":[{\"op\":\"GET /a\",\"request\":" + rule + "}]}]", Seg, "")));
                Assert.Equal("unsafe", Outcome(Body("{}", "[" + SvcHead + ",\"ops\":[{\"op\":\"GET /a\",\"response\":" + rule + "}]}]", Seg, "")));
                Assert.NotEmpty(what);
            }
        }
        Assert.Equal("accepted", Outcome(Body("{\"request\":{\"headers\":{\"authorization\":{\"action\":\"drop\"}}}}", "[]", Seg, "")));
    }

    [Fact]
    public void H2GlobalStar()
    {
        string keep = "{\"response\":{\"body\":[{\"path\":\"$.a.*\",\"action\":{\"action\":\"keep\"}}]}}";
        string hmac = "{\"response\":{\"body\":[{\"path\":\"$.items[*].*\",\"action\":{\"action\":\"hmac\",\"domain\":\"tok\"}}]}}";
        string drop = "{\"response\":{\"body\":[{\"path\":\"$.a.*\",\"action\":{\"action\":\"drop\"}}]}}";
        Assert.Equal("unsafe", Outcome(Body(keep, "[]", Seg, "")));
        Assert.Equal("unsafe", Outcome(Body(hmac, "[]", Seg, "")));
        Assert.Equal("accepted", Outcome(Body(drop, "[]", Seg, "")));
        string rule = "{\"body\":[{\"path\":\"$.*\",\"action\":{\"action\":\"keep\"}}]}";
        Assert.Equal("accepted", Outcome(Body("{}", "[" + SvcHead + ",\"request\":" + rule + ",\"ops\":[]}]", Seg, "")));
        Assert.Equal("accepted", Outcome(Body("{}", "[" + SvcHead + ",\"ops\":[{\"op\":\"GET /a\",\"response\":" + rule + "}]}]", Seg, "")));
    }

    [Fact]
    public void H3Windows()
    {
        var created = DateTimeOffset.Parse(Created, CultureInfo.InvariantCulture);
        foreach (int extra in new[] { 0, 1 })
        {
            string when = created.AddDays(7).AddSeconds(extra).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
            string expect = extra == 0 ? "accepted" : "unsafe";
            Assert.Equal(expect, Outcome(Body("{}", "[]", Seg, "{\"enabled\":true,\"expires_at\":\"" + when + "\"}")));
            string seg = "{\"auto_words\":true,\"auto_words_expires_at\":\"" + when + "\",\"allow\":[],\"hosts_allow\":[]}";
            Assert.Equal(expect, Outcome(Body("{}", "[]", seg, "")));
        }
        Assert.Equal("accepted", Outcome(Body("{}", "[]", Seg, "{\"enabled\":false,\"expires_at\":\"2026-12-20T08:00:00Z\"}")));
    }
}
