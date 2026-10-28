using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using TrafficTwin.Sdk.Tests.Helpers;
using Xunit;

namespace TrafficTwin.Sdk.Tests;

/// <summary>Inbound capture of the ASP.NET Core middleware on TestServer (and on Kestrel where the raw target matters).</summary>
public class InboundTests
{
    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement.Clone();

    private static Dictionary<string, object?> WithOps(Dictionary<string, object?> policy, params (string op, Dictionary<string, object?>? request, Dictionary<string, object?>? response)[] extra)
    {
        var svc = (Dictionary<string, object?>)((List<object?>)policy["services"]!)[0]!;
        var ops = (List<object?>)svc["ops"]!;
        foreach (var (op, rq, rs) in extra)
        {
            var m = PolicyFactory.Map(("op", op));
            if (rq != null) m["request"] = rq;
            if (rs != null) m["response"] = rs;
            ops.Add(m);
        }
        return policy;
    }

    /// <summary>The inbound events (on Kestrel the test client is itself an HttpClient of the process and is captured as outbound).</summary>
    private static async Task<List<JsonElement>> Events(FakeCore core, Sut sut, int n)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        List<JsonElement> inbound;
        do
        {
            await sut.Agent!.FlushAsync();
            inbound = core.Events.Select(Parse).Where(e => e.GetProperty("dir").GetString() == "inbound").ToList();
            if (inbound.Count >= n) break;
            await Task.Delay(30);
        } while (sw.ElapsedMilliseconds < 15000);
        return inbound;
    }

    private static Dictionary<string, object?> ShopSvcPolicy(Action<Dictionary<string, object?>>? tweak = null, long maxBody = 1048576, long rateBp = 10000)
    {
        var p = PolicyFactory.Shop(maxBodyBytes: maxBody, rateBp: rateBp);
        tweak?.Invoke(p);
        return p;
    }

    [Fact]
    public async Task FrameworkRouteOfAMappedGroupIsUsedAsTemplate()
    {
        var policy = WithOps(PolicyFactory.Shop(),
            ("GET /api/v2/orders/{id}", PolicyFactory.Map(("path", PolicyFactory.Map(("id", PolicyFactory.Hmac("order"))))), null));
        await using var core = await FakeCore.StartAsync(policy);
        await using var sut = await Sut.StartAsync(new SutOptions
        {
            Core = core,
            Endpoints = app =>
            {
                var g = app.MapGroup("/api").MapGroup("/v2");
                g.MapGet("/orders/{id:int:min(1)}", (int id) => "order " + id);
                g.MapGet("/other/{x}", (string x) => x);
            },
        });
        await sut.WaitCapturingAsync();
        await sut.Client.GetAsync("/api/v2/orders/184");
        await sut.Client.GetAsync("/api/v2/other/184");
        var ev = await Events(core, sut, 2);
        var a = ev.Single(e => e.GetProperty("op").GetString() == "GET /api/v2/orders/{id}");
        Assert.Equal("framework", a.GetProperty("route_source").GetString());
        Assert.StartsWith("/api/v2/orders/{tk1:k1:", a.GetProperty("req").GetProperty("path").GetString());
        // No policy operation for this endpoint: the path is shapes only, the framework template never appears.
        var b = ev.Single(e => e.GetProperty("op").GetString() != "GET /api/v2/orders/{id}");
        Assert.Equal("raw", b.GetProperty("route_source").GetString());
        Assert.Equal("GET /{drop:str:l8}/{drop:str:l8}/{drop:str:l8}/{drop:str:digits}", b.GetProperty("op").GetString());
        Assert.DoesNotContain("other", b.GetRawText());
    }

    [Fact]
    public async Task PolicyTemplateMatchesWhenTheFrameworkRouteIsNotNormalizable()
    {
        var policy = WithOps(PolicyFactory.Shop(),
            ("GET /files/{name}", PolicyFactory.Map(("path", PolicyFactory.Map(("name", PolicyFactory.Hmac("file"))))), null));
        await using var core = await FakeCore.StartAsync(policy);
        await using var sut = await Sut.StartAsync(new SutOptions
        {
            Core = core,
            // "{*rest}" is a catch-all: not normalizable (3.4), so the policy template of 3.3 point 2 decides.
            Endpoints = app => app.MapGet("/files/{*rest}", (string rest) => rest),
        });
        await sut.WaitCapturingAsync();
        await sut.Client.GetAsync("/files/report");
        var ev = (await Events(core, sut, 1)).Single();
        Assert.Equal("policy", ev.GetProperty("route_source").GetString());
        Assert.Equal("GET /files/{name}", ev.GetProperty("op").GetString());
    }

    [Fact]
    public async Task PathBaseIsPartOfTheFrameworkRoute()
    {
        var policy = WithOps(PolicyFactory.Shop(),
            ("GET /shop/items/{id}", PolicyFactory.Map(("path", PolicyFactory.Map(("id", PolicyFactory.Hmac("item"))))), null));
        await using var core = await FakeCore.StartAsync(policy);
        await using var sut = await Sut.StartAsync(new SutOptions
        {
            Core = core,
            PreMiddleware = app => { app.UsePathBase("/shop"); app.UseRouting(); },
            Endpoints = app => app.MapGet("/items/{id}", (string id) => id),
        });
        await sut.WaitCapturingAsync();
        await sut.Client.GetAsync("/shop/items/77");
        var ev = (await Events(core, sut, 1)).Single();
        Assert.Equal("GET /shop/items/{id}", ev.GetProperty("op").GetString());
        Assert.Equal("framework", ev.GetProperty("route_source").GetString());
    }

    [Fact]
    public async Task TraceparentIsReadAndNothingIsInjected()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Add("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
        var res = await sut.Client.SendAsync(req);
        Assert.False(res.Headers.Contains("traceparent"));
        var ev = (await Events(core, sut, 1)).Single();
        Assert.Equal("4bf92f3577b34da6a3ce929d0e0e4736", ev.GetProperty("trace_id").GetString());
        Assert.Equal("00f067aa0ba902b7", ev.GetProperty("parent_span_id").GetString());
        Assert.Equal("trace", ev.GetProperty("sampled_by").GetString());
        Assert.Matches("^[0-9a-f]{16}$", ev.GetProperty("span_id").GetString());
    }

    [Fact]
    public async Task InvalidTraceparentIsIgnored()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.TryAddWithoutValidation("traceparent", "00-00000000000000000000000000000000-00f067aa0ba902b7-01");
        await sut.Client.SendAsync(req);
        var ev = (await Events(core, sut, 1)).Single();
        Assert.Equal("random", ev.GetProperty("sampled_by").GetString());
        Assert.False(ev.TryGetProperty("parent_span_id", out _));
        Assert.Matches("^[0-9a-f]{32}$", ev.GetProperty("trace_id").GetString());
    }

    [Fact]
    public async Task SubjectFromTheHeaderDecidesAndIsTokenized()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        for (int i = 0; i < 2; i++)
        {
            var req = new HttpRequestMessage(HttpMethod.Get, "/health");
            req.Headers.Add("X-Customer", "Bearer cust-0042");
            await sut.Client.SendAsync(req);
        }
        var ev = await Events(core, sut, 2);
        Assert.Equal(ev[0].GetProperty("subject").GetString(), ev[1].GetProperty("subject").GetString());
        Assert.DoesNotContain("cust-0042", string.Join("", core.OtlpRequests));
        Assert.All(ev, e => Assert.Equal("subject", e.GetProperty("sampled_by").GetString()));
        // "Bearer " is removed before hashing (11 step 2): the same subject without the prefix gives the same token.
        var plain = new HttpRequestMessage(HttpMethod.Get, "/health");
        plain.Headers.Add("X-Customer", "cust-0042");
        await sut.Client.SendAsync(plain);
        var ev3 = await Events(core, sut, 3);
        Assert.Equal(ev[0].GetProperty("subject").GetString(), ev3[2].GetProperty("subject").GetString());
    }

    [Fact]
    public async Task BaggageDecidesOnlyForInternalServicesThatTrustIt()
    {
        // trust_baggage + internal: tt.s=0 prevents the capture even at 100%, tt.s=1 forces it even at 0%.
        var p = PolicyFactory.Shop(rateBp: 0, trustBaggage: true, internalService: true);
        await using var core = await FakeCore.StartAsync(p);
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        var off = new HttpRequestMessage(HttpMethod.Get, "/health");
        off.Headers.Add("baggage", "userId=alice, tt.s=1 ;prop=x");
        await sut.Client.SendAsync(off);
        await sut.Client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "/health")); // no baggage, rate 0
        var ev = (await Events(core, sut, 1)).Single();
        Assert.Equal("baggage", ev.GetProperty("sampled_by").GetString());
        Assert.Equal(1, sut.Agent!.Status().ExchangesSampled);

        // A border service (internal=false) never reads the baggage: an outsider cannot force the capture.
        var p2 = PolicyFactory.Shop(rateBp: 0, trustBaggage: true, internalService: false);
        await using var core2 = await FakeCore.StartAsync(p2);
        await using var sut2 = await Sut.StartAsync(new SutOptions { Core = core2 });
        await sut2.WaitCapturingAsync();
        var forced = new HttpRequestMessage(HttpMethod.Get, "/health");
        forced.Headers.Add("baggage", "tt.s=1");
        await sut2.Client.SendAsync(forced);
        await sut2.Agent!.FlushAsync();
        await Task.Delay(300);
        Assert.Empty(core2.Events);
    }

    [Fact]
    public async Task BodyOverTheLimitIsTruncatedButTheAppReadsEverything()
    {
        await using var core = await FakeCore.StartAsync(ShopSvcPolicy(maxBody: 64));
        await using var sut = await Sut.StartAsync(new SutOptions
        {
            Core = core,
            Endpoints = app => app.MapPost("/big", async (HttpContext c) =>
            {
                long n = 0;
                var buf = new byte[1000];
                int r;
                while ((r = await c.Request.Body.ReadAsync(buf)) > 0) n += r;
                c.Response.ContentType = "application/json";
                return Results.Text("{\"read\":" + n + ",\"pad\":\"" + new string('x', 500) + "\"}", "application/json");
            }),
        });
        await sut.WaitCapturingAsync();
        var content = new StringContent("{\"a\":\"" + new string('y', 5000) + "\"}", Encoding.UTF8, "application/json");
        var res = await sut.Client.PostAsync("/big", content);
        string body = await res.Content.ReadAsStringAsync();
        Assert.StartsWith("{\"read\":5008", body);
        var ev = (await Events(core, sut, 1)).Single();
        Assert.Equal("trunc:size", ev.GetProperty("req").GetProperty("body").GetString());
        Assert.Equal("lmax", ev.GetProperty("req").GetProperty("size").GetString());
        Assert.Equal("trunc:size", ev.GetProperty("resp").GetProperty("body").GetString());
        Assert.DoesNotContain("yyyy", string.Join("", core.OtlpRequests));
    }

    [Fact]
    public async Task RequestBodyTheAppDidNotReadIsNotConsumed()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions
        {
            Core = core,
            Endpoints = app => app.MapPost("/ignore", () => "ignored"),
        });
        await sut.WaitCapturingAsync();
        var res = await sut.Client.PostAsync("/ignore", new StringContent("{\"secret\":\"Giulia Neri\"}", Encoding.UTF8, "application/json"));
        Assert.Equal("ignored", await res.Content.ReadAsStringAsync());
        var ev = (await Events(core, sut, 1)).Single();
        Assert.Equal("trunc:size", ev.GetProperty("req").GetProperty("body").GetString());
        Assert.Equal("lmax", ev.GetProperty("req").GetProperty("size").GetString());
    }

    [Fact]
    public async Task HeadAndNoContentResponsesHaveNoBody()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions
        {
            Core = core,
            Endpoints = app =>
            {
                app.MapMethods("/hd", new[] { "GET", "HEAD" }, () => Results.Text("hello", "text/plain"));
                app.MapGet("/nc", () => Results.NoContent());
            },
        });
        await sut.WaitCapturingAsync();
        await sut.Client.SendAsync(new HttpRequestMessage(HttpMethod.Head, "/hd"));
        await sut.Client.GetAsync("/nc");
        var ev = await Events(core, sut, 2);
        foreach (var e in ev)
        {
            Assert.False(e.GetProperty("resp").TryGetProperty("body", out _));
            Assert.Equal("l8", e.GetProperty("resp").GetProperty("size").GetString());
        }
    }

    [Fact]
    public async Task GzippedBodiesAreDecodedBySanitizer()
    {
        var policy = WithOps(PolicyFactory.Shop(),
            ("POST /gz", PolicyFactory.Map(("body", PolicyFactory.List(PolicyFactory.Rule("$.kind", PolicyFactory.Keep())))),
                PolicyFactory.Map(("body", PolicyFactory.List(PolicyFactory.Rule("$.status", PolicyFactory.Keep()))))));
        await using var core = await FakeCore.StartAsync(policy);
        await using var sut = await Sut.StartAsync(new SutOptions
        {
            Core = core,
            Endpoints = app => app.MapPost("/gz", async (HttpContext c) =>
            {
                using var ms = new MemoryStream();
                await c.Request.Body.CopyToAsync(ms);
                c.Response.ContentType = "application/json";
                c.Response.Headers.ContentEncoding = "gzip";
                using var o = new MemoryStream();
                using (var gz = new GZipStream(o, CompressionLevel.Optimal, true)) gz.Write(Encoding.UTF8.GetBytes("{\"status\":\"OK\",\"who\":\"Giulia\"}"));
                await c.Response.Body.WriteAsync(o.ToArray());
            }),
        });
        await sut.WaitCapturingAsync();
        using var body = new MemoryStream();
        using (var gz = new GZipStream(body, CompressionLevel.Optimal, true)) gz.Write(Encoding.UTF8.GetBytes("{\"kind\":\"gift\",\"to\":\"Giulia\"}"));
        var content = new ByteArrayContent(body.ToArray());
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        content.Headers.ContentEncoding.Add("gzip");
        var res = await sut.Client.PostAsync("/gz", content);
        Assert.Equal(System.Net.HttpStatusCode.OK, res.StatusCode);
        var ev = (await Events(core, sut, 1)).Single();
        Assert.Equal("keep:gift", ev.GetProperty("req").GetProperty("body").GetProperty("kind").GetString());
        Assert.Equal("drop:str:l8", ev.GetProperty("req").GetProperty("body").GetProperty("to").GetString());
        Assert.Equal("keep:OK", ev.GetProperty("resp").GetProperty("body").GetProperty("status").GetString());
        Assert.DoesNotContain("Giulia", string.Join("", core.OtlpRequests));
    }

    [Fact]
    public async Task UnsupportedEncodingIsDropped()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions
        {
            Core = core,
            Endpoints = app => app.MapPost("/br", async (HttpContext c) => { await c.Request.Body.CopyToAsync(Stream.Null); return "ok"; }),
        });
        await sut.WaitCapturingAsync();
        var content = new ByteArrayContent(new byte[] { 1, 2, 3, 4 });
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        content.Headers.ContentEncoding.Add("br");
        await sut.Client.PostAsync("/br", content);
        var ev = (await Events(core, sut, 1)).Single();
        Assert.Equal("drop:bytes", ev.GetProperty("req").GetProperty("body").GetString());
        Assert.False(ev.GetProperty("req").TryGetProperty("size", out _));
    }

    [Fact]
    public async Task ManyConcurrentRequestsAreAllCapturedWithoutCrossTalk()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        var tasks = Enumerable.Range(0, 200).Select(async i =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, "/orders/ORD-" + (100000 + i));
            req.Headers.Add("traceparent", "00-" + i.ToString("x32") + "-" + (i + 1).ToString("x16") + "-01");
            var res = await sut.Client.SendAsync(req);
            Assert.Equal(System.Net.HttpStatusCode.OK, res.StatusCode);
        });
        await Task.WhenAll(tasks);
        var ev = await Events(core, sut, 200);
        Assert.Equal(200, ev.Count);
        Assert.Equal(200, ev.Select(e => e.GetProperty("trace_id").GetString()).Distinct().Count());
        Assert.Equal(200, ev.Select(e => e.GetProperty("req").GetProperty("path").GetString()).Distinct().Count());
        Assert.Equal(0, sut.Agent!.Status().EventsDroppedQueue);
    }

    [Fact]
    public async Task LargeStreamedResponseIsDeliveredUnchanged()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        byte[] payload = new byte[5 * 1024 * 1024];
        new Random(7).NextBytes(payload);
        await using var sut = await Sut.StartAsync(new SutOptions
        {
            UseKestrel = true,
            Core = core,
            Endpoints = app => app.MapGet("/blob", async (HttpContext c) =>
            {
                c.Response.ContentType = "application/octet-stream";
                c.Response.ContentLength = payload.Length;
                for (int i = 0; i < payload.Length; i += 65536) await c.Response.Body.WriteAsync(payload.AsMemory(i, Math.Min(65536, payload.Length - i)));
            }),
        });
        await sut.WaitCapturingAsync();
        var res = await sut.Client.GetAsync("/blob");
        byte[] got = await res.Content.ReadAsByteArrayAsync();
        Assert.True(payload.AsSpan().SequenceEqual(got));
        Assert.Equal(payload.Length, res.Content.Headers.ContentLength);
        var ev = (await Events(core, sut, 1)).Single();
        Assert.Equal("trunc:size", ev.GetProperty("resp").GetProperty("body").GetString());
        Assert.Equal("lmax", ev.GetProperty("resp").GetProperty("size").GetString());
    }

    [Fact]
    public async Task RawTargetKeepsPercentEncodingOnKestrel()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { UseKestrel = true, Core = core });
        await sut.WaitCapturingAsync();
        // Decoded, "a/b" would be two segments; the raw target has one.
        await sut.Client.GetAsync("/orders/a%2Fb");
        var ev = (await Events(core, sut, 1)).Single();
        Assert.Equal("GET /orders/{id}", ev.GetProperty("op").GetString());
        Assert.StartsWith("/orders/{tk1:k1:", ev.GetProperty("req").GetProperty("path").GetString());
    }

    [Fact]
    public async Task ServerErrorStatusIsReported()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions
        {
            UseKestrel = true,
            Core = core,
            Endpoints = app => app.MapGet("/throw", (HttpContext _) => { throw new InvalidOperationException("secret: Giulia"); }),
        });
        await sut.WaitCapturingAsync();
        var res = await sut.Client.GetAsync("/throw");
        Assert.Equal(System.Net.HttpStatusCode.InternalServerError, res.StatusCode);
        var ev = (await Events(core, sut, 1)).Single();
        Assert.Equal(500, ev.GetProperty("status").GetInt32());
        Assert.DoesNotContain("Giulia", string.Join("", core.OtlpRequests));
    }

    [Fact]
    public async Task QueryAndCookiesAreShapesOnly()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { UseKestrel = true, Core = core });
        await sut.WaitCapturingAsync();
        var req = new HttpRequestMessage(HttpMethod.Get, "/echo?email=giulia.neri%40example.com&ORD2026000184&n=1&n=2");
        req.Headers.Add("Cookie", "sid=9f8e7d6c5b4a; theme=dark");
        await sut.Client.SendAsync(req);
        var ev = (await Events(core, sut, 1)).Single();
        var q = ev.GetProperty("req").GetProperty("query");
        Assert.Equal("drop:str:email", q.GetProperty("email")[0].GetString());
        Assert.Equal("drop:str:l32", q.GetProperty("{*}")[0].GetString());
        Assert.Equal(2, q.GetProperty("n").GetArrayLength());
        var c = ev.GetProperty("req").GetProperty("cookies");
        Assert.Equal("drop:str:l32", c.GetProperty("sid")[0].GetString());
        Assert.DoesNotContain("giulia", string.Join("", core.OtlpRequests));
        Assert.DoesNotContain("9f8e7d6c5b4a", string.Join("", core.OtlpRequests));
        Assert.False(ev.GetProperty("req").GetProperty("headers").TryGetProperty("cookie", out _));
    }
}
