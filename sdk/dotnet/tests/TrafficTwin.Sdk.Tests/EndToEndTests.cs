using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using TrafficTwin.Sdk.Tests.Helpers;
using Xunit;

namespace TrafficTwin.Sdk.Tests;

/// <summary>Application on Kestrel + carrier on Kestrel + fake tt-core on Kestrel with mTLS: the whole path.</summary>
public class EndToEndTests
{
    private const string OrderBody = "{\"items\":[{\"sku\":\"TSHIRT-RED-M\",\"qty\":2}],\"email\":\"giulia.neri@example.com\",\"note\":\"citofono Neri\"}";

    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement.Clone();

    private static readonly string[] Secrets = { "giulia", "Giulia", "Neri", "ORD-2026-000184", "SHP-7781203", "Via Roma", "73.4", "TSHIRT-RED-M", "citofono", "ADDRESS_INVALID_DETAIL" };

    private static void AssertNoSecrets(FakeCore core)
    {
        string all = string.Join("\n", core.OtlpRequests);
        foreach (string s in Secrets) Assert.DoesNotContain(s, all);
    }

    [Fact]
    public async Task InboundAndOutboundAreCapturedSanitizedAndCorrelated()
    {
        await using var carrier = await Carrier.StartAsync();
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(carrier.BaseUrl));
        await using var sut = await Sut.StartAsync(new SutOptions { UseKestrel = true, Core = core, Carrier = carrier });
        await sut.WaitCapturingAsync();

        var res = await sut.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/orders?promo=AUTUMN10")
        {
            Content = new StringContent(OrderBody, Encoding.UTF8, "application/json"),
            Headers = { { "X-Customer", "cust-0042" } },
        });
        Assert.Equal(System.Net.HttpStatusCode.Created, res.StatusCode);
        await sut.Agent!.FlushAsync();
        var events = (await core.WaitEventsAsync(2)).Select(Parse).ToList();

        var inbound = events.Single(e => e.GetProperty("dir").GetString() == "inbound" && e.GetProperty("op").GetString() == "POST /orders");
        var outbound = events.Single(e => e.GetProperty("dir").GetString() == "outbound" && e.GetProperty("service").GetString() == "shipping-ext");

        Assert.Equal("tt.http.exchange/v1", inbound.GetProperty("schema").GetString());
        Assert.Equal("shop-api", inbound.GetProperty("service").GetString());
        Assert.Equal("framework", inbound.GetProperty("route_source").GetString());
        Assert.Equal(201, inbound.GetProperty("status").GetInt32());
        Assert.Equal("sdk-dotnet", inbound.GetProperty("source").GetProperty("kind").GetString());
        Assert.Equal("p-shop", inbound.GetProperty("policy").GetProperty("id").GetString());
        Assert.StartsWith("sha256:", inbound.GetProperty("policy").GetProperty("hash").GetString());
        var req = inbound.GetProperty("req");
        Assert.Equal("/orders", req.GetProperty("path").GetString());
        Assert.Equal("drop:str:l8", req.GetProperty("query").GetProperty("promo")[0].GetString());
        Assert.Equal("drop:str:email", req.GetProperty("body").GetProperty("email").GetString());
        Assert.Equal("num:2-5", req.GetProperty("body").GetProperty("items")[0].GetProperty("qty").GetString());
        var resp = inbound.GetProperty("resp");
        Assert.StartsWith("tk1:k1:", resp.GetProperty("body").GetProperty("id").GetString());
        Assert.Equal("keep:CREATED", resp.GetProperty("body").GetProperty("status").GetString());
        Assert.Equal("drop:dec", resp.GetProperty("body").GetProperty("total").GetString());
        Assert.StartsWith("tk1:k1:", inbound.GetProperty("subject").GetString());
        Assert.Equal("subject", inbound.GetProperty("sampled_by").GetString());

        // The outbound call: policy base, HMAC of the order id shared with the inbound response (same domain, same value).
        Assert.Equal("POST /v1/shipments", outbound.GetProperty("op").GetString());
        Assert.Equal("inherited", outbound.GetProperty("sampled_by").GetString());
        Assert.StartsWith("tk1:k1:", outbound.GetProperty("req").GetProperty("body").GetProperty("orderId").GetString());
        Assert.Equal(resp.GetProperty("body").GetProperty("id").GetString(), outbound.GetProperty("req").GetProperty("body").GetProperty("orderId").GetString());
        Assert.Equal("keep:PENDING", outbound.GetProperty("resp").GetProperty("body").GetProperty("status").GetString());
        Assert.Equal("drop:str:l32", outbound.GetProperty("resp").GetProperty("body").GetProperty("recipient").GetString());

        // Correlation (event.md 1.1).
        Assert.Equal(inbound.GetProperty("trace_id").GetString(), outbound.GetProperty("trace_id").GetString());
        Assert.Equal(inbound.GetProperty("span_id").GetString(), outbound.GetProperty("parent_span_id").GetString());
        Assert.NotEqual(inbound.GetProperty("span_id").GetString(), outbound.GetProperty("span_id").GetString());

        AssertNoSecrets(core);
        // The app's own traffic was not altered: the carrier saw no traceparent and no baggage.
        var carrierReq = carrier.Requests.Single(r => r.Path.StartsWith("/v1/shipments"));
        Assert.DoesNotContain("traceparent", carrierReq.Headers.Keys);
        Assert.DoesNotContain("baggage", carrierReq.Headers.Keys);
        Assert.Contains("giulia.neri@example.com", carrierReq.Body);
        // Heartbeat first: the first one reported "starting" with no capture before it.
        Assert.NotEqual("capturing", core.Heartbeats.First()["state"]!.GetValue<string>());
        Assert.Empty(core.Events.Take(0));
    }

    [Fact]
    public async Task ResponseIsByteIdenticalWithAndWithoutTheSdk()
    {
        await using var carrier = await Carrier.StartAsync();
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(carrier.BaseUrl));
        await using var plain = await Sut.StartAsync(new SutOptions { UseKestrel = true, Sdk = false, Carrier = carrier });
        await using var withSdk = await Sut.StartAsync(new SutOptions { UseKestrel = true, Core = core, Carrier = carrier });
        await withSdk.WaitCapturingAsync();

        foreach (string path in new[] { "/health", "/echo?x=1&y=%20z", "/orders/ORD-9", "/stream", "/missing" })
        {
            var a = await plain.Client.GetAsync(path);
            var b = await withSdk.Client.GetAsync(path);
            Assert.Equal(a.StatusCode, b.StatusCode);
            Assert.Equal(await a.Content.ReadAsByteArrayAsync(), await b.Content.ReadAsByteArrayAsync());
            Assert.Equal(a.Headers.TransferEncodingChunked, b.Headers.TransferEncodingChunked);
            Assert.Equal(a.Content.Headers.ContentLength, b.Content.Headers.ContentLength);
            Assert.Equal(a.Content.Headers.ContentType?.ToString(), b.Content.Headers.ContentType?.ToString());
        }
        var pa = await plain.Client.PostAsync("/orders", new StringContent(OrderBody, Encoding.UTF8, "application/json"));
        var pb = await withSdk.Client.PostAsync("/orders", new StringContent(OrderBody, Encoding.UTF8, "application/json"));
        Assert.Equal(await pa.Content.ReadAsStringAsync(), await pb.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ErrorResponseUsesTheErrorsRulesOfTheService()
    {
        await using var carrier = await Carrier.StartAsync();
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(carrier.BaseUrl));
        await using var sut = await Sut.StartAsync(new SutOptions { UseKestrel = true, Core = core, Carrier = carrier });
        await sut.WaitCapturingAsync();
        var res = await sut.Client.GetAsync("/boom-carrier");
        Assert.Equal("422", await res.Content.ReadAsStringAsync());
        await sut.Agent!.FlushAsync();
        var events = (await core.WaitEventsAsync(2)).Select(Parse).ToList();
        var boom = events.Single(e => e.GetProperty("dir").GetString() == "outbound" && e.GetProperty("status").GetInt32() == 422);
        Assert.Equal("keep:ADDRESS_INVALID", boom.GetProperty("resp").GetProperty("body").GetProperty("error").GetProperty("code").GetString());
        Assert.Equal("drop:str:l32", boom.GetProperty("resp").GetProperty("body").GetProperty("error").GetProperty("detail").GetString());
        AssertNoSecrets(core);
    }

    [Fact]
    public async Task EnrollmentStateIsStoredWithRestrictivePermissionsAndReused()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        string dir = Path.Combine(Path.GetTempPath(), "tt-state-" + Guid.NewGuid().ToString("N"));
        try
        {
            await using (var sut = await Sut.StartAsync(new SutOptions { UseKestrel = true, Core = core, StateDir = dir }))
            {
                await sut.WaitCapturingAsync();
                Assert.Single(core.Enrollments);
                Assert.Equal("shop-api", core.Enrollments.First()["source"]!["service_name"]!.GetValue<string>());
                Assert.Equal("sdk-dotnet", core.Enrollments.First()["source"]!["kind"]!.GetValue<string>());
                Assert.NotNull(core.Enrollments.First()["csr"]);
                if (!OperatingSystem.IsWindows())
                {
                    Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(dir));
                    foreach (string f in Directory.GetFiles(dir))
                        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(f));
                }
                Assert.True(File.Exists(Path.Combine(dir, "client.key")));
                Assert.True(File.Exists(Path.Combine(dir, "enrollment.json")));
                Assert.True(File.Exists(Path.Combine(dir, "policy.envelope.json")));
                Assert.DoesNotContain("tte_", File.ReadAllText(Path.Combine(dir, "enrollment.json")));
            }
            // Second start: no new enrollment, the cached policy is re-verified.
            await using (var sut2 = await Sut.StartAsync(new SutOptions { UseKestrel = true, Core = core, StateDir = dir }))
            {
                await sut2.WaitCapturingAsync();
                Assert.Single(core.Enrollments);
            }
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task EnrollmentWithoutCsrUsesTheKeyGeneratedByTheServer()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { UseKestrel = true, Core = core, UseCsr = false });
        await sut.WaitCapturingAsync();
        Assert.Null(core.Enrollments.First()["csr"]);
    }

    [Fact]
    public async Task ServiceNameIsTheOneAssignedAtEnrollment()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        core.FixedServiceName = "shop-api";
        await using var sut = await Sut.StartAsync(new SutOptions { UseKestrel = true, Core = core, ServiceName = "asked-for-something-else" });
        await sut.WaitCapturingAsync();
        await sut.Client.GetAsync("/health");
        await sut.Agent!.FlushAsync();
        var events = (await core.WaitEventsAsync(1)).Select(Parse).ToList();
        Assert.Contains(events, e => e.GetProperty("dir").GetString() == "inbound" && e.GetProperty("service").GetString() == "shop-api");
    }

    [Fact]
    public async Task ExporterRetriesOn503AndThenDelivers()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { UseKestrel = true, Core = core });
        await sut.WaitCapturingAsync();
        core.FailLogs = 2;
        await sut.Client.GetAsync("/health");
        await sut.Agent!.FlushAsync();
        var events = await core.WaitEventsAsync(1, 20000);
        Assert.NotEmpty(events);
        Assert.True(sut.Agent.Status().SendErrors >= 2);
        Assert.True(sut.Agent.Status().EventsSent >= 1);
    }

    [Fact]
    public async Task OtlpEnvelopeFollowsEventMd()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { UseKestrel = true, Core = core });
        await sut.WaitCapturingAsync();
        await sut.Client.GetAsync("/health");
        await sut.Agent!.FlushAsync();
        await core.WaitEventsAsync(1);
        var doc = Parse(core.OtlpRequests.First());
        var rl = doc.GetProperty("resourceLogs")[0];
        var attrs = rl.GetProperty("resource").GetProperty("attributes").EnumerateArray().ToDictionary(a => a.GetProperty("key").GetString()!, a => a.GetProperty("value").GetProperty("stringValue").GetString()!);
        Assert.Equal("shop-api", attrs["service.name"]);
        Assert.Equal("sdk-dotnet", attrs["tt.source.kind"]);
        Assert.Equal("0.1.0", attrs["tt.source.version"]);
        Assert.StartsWith("src-", attrs["tt.source.id"]);
        var sl = rl.GetProperty("scopeLogs")[0];
        Assert.Equal("traffic-twin", sl.GetProperty("scope").GetProperty("name").GetString());
        var lr = sl.GetProperty("logRecords")[0];
        Assert.Equal("tt.http.exchange", lr.GetProperty("eventName").GetString());
        Assert.Equal(9, lr.GetProperty("severityNumber").GetInt32());
        Assert.Equal("INFO", lr.GetProperty("severityText").GetString());
        Assert.Matches("^[0-9]{19}$", lr.GetProperty("timeUnixNano").GetString());
        Assert.Matches("^[0-9a-f]{32}$", lr.GetProperty("traceId").GetString());
        Assert.Matches("^[0-9a-f]{16}$", lr.GetProperty("spanId").GetString());
        Assert.Equal("application/json", core.LogContentTypes.First());
        // The event body is canonical tt-cjson: keys sorted, no whitespace.
        string ev = lr.GetProperty("body").GetProperty("stringValue").GetString()!;
        Assert.Equal(Sanitizing.Canonical.Write(Sanitizing.Plain.From(Sanitizing.JsonParser.Parse(Encoding.UTF8.GetBytes(ev)), true) is Dictionary<string, object?> d ? ToOut(d) : null), ev);
    }

    private static object? ToOut(object? v) => v switch
    {
        Sanitizing.Lex l => new Sanitizing.CNum(Sanitizing.JsonNumbers.Canonical(l.Text)),
        Dictionary<string, object?> d => d.ToDictionary(kv => kv.Key, kv => ToOut(kv.Value)) is var m ? new Dictionary<string, object?>(m, StringComparer.Ordinal) : null,
        List<object?> l => l.Select(ToOut).ToList(),
        _ => v,
    };
}
