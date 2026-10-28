using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TrafficTwin.Sdk.Tests.Helpers;
using Xunit;

namespace TrafficTwin.Sdk.Tests;

/// <summary>Outbound capture: the DelegatingHandler, the HttpHandlerDiagnosticListener fallback, propagation, streaming.</summary>
public class OutboundTests
{
    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement.Clone();

    private static async Task<List<JsonElement>> Outbound(FakeCore core, Sut sut, int n)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        List<JsonElement> list;
        do
        {
            await sut.Agent!.FlushAsync();
            list = core.Events.Select(Parse).Where(e => e.GetProperty("dir").GetString() == "outbound").ToList();
            if (list.Count >= n) break;
            await Task.Delay(30);
        } while (sw.ElapsedMilliseconds < 15000);
        return list;
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> f;
        public StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> f) { this.f = f; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => f(request, cancellationToken);
    }

    [Fact]
    public async Task StandaloneHandlerCapturesBodiesAndLeavesTheTrafficAlone()
    {
        await using var carrier = await Carrier.StartAsync();
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(carrier.BaseUrl));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        using var http = new HttpClient(new TrafficTwinHandler(sut.Agent!, new SocketsHttpHandler()));
        const string reqBody = "{\"orderId\":\"ORD-2026-000184\",\"to\":\"giulia.neri@example.com\"}";
        var res = await http.PostAsync(carrier.BaseUrl + "/v1/shipments?express=yes", new StringContent(reqBody, Encoding.UTF8, "application/json"));
        string resBody = await res.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.Created, res.StatusCode);
        Assert.Contains("SHP-7781203", resBody);
        var got = carrier.Requests.Single();
        Assert.Equal(reqBody, got.Body);
        Assert.Equal(Encoding.UTF8.GetByteCount(reqBody).ToString(), got.Headers["content-length"]);
        Assert.DoesNotContain("traceparent", got.Headers.Keys);
        var ev = (await Outbound(core, sut, 1)).Single();
        Assert.Equal("shipping-ext", ev.GetProperty("service").GetString());
        Assert.Equal("POST /v1/shipments", ev.GetProperty("op").GetString());
        Assert.Equal("random", ev.GetProperty("sampled_by").GetString());
        Assert.Equal(201, ev.GetProperty("status").GetInt32());
        Assert.StartsWith("tk1:k1:", ev.GetProperty("req").GetProperty("body").GetProperty("orderId").GetString());
        Assert.Equal("drop:str:email", ev.GetProperty("req").GetProperty("body").GetProperty("to").GetString());
        Assert.Equal("keep:PENDING", ev.GetProperty("resp").GetProperty("body").GetProperty("status").GetString());
        Assert.Equal("drop:str:l8", ev.GetProperty("req").GetProperty("query").GetProperty("express")[0].GetString());
        Assert.DoesNotContain("giulia", string.Join("", core.OtlpRequests));
        Assert.False(ev.TryGetProperty("parent_span_id", out _));
    }

    [Fact]
    public async Task ResponseNobodyReadsIsReportedAsNotConsumed()
    {
        await using var carrier = await Carrier.StartAsync();
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(carrier.BaseUrl));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        using var http = new HttpClient(new TrafficTwinHandler(sut.Agent!, new SocketsHttpHandler()));
        using (var res = await http.SendAsync(new HttpRequestMessage(HttpMethod.Post, carrier.BaseUrl + "/v1/shipments") { Content = new StringContent("{}", Encoding.UTF8, "application/json") }, HttpCompletionOption.ResponseHeadersRead)) { }
        var ev = (await Outbound(core, sut, 1)).Single();
        Assert.Equal("trunc:size", ev.GetProperty("resp").GetProperty("body").GetString());
        Assert.Equal("lmax", ev.GetProperty("resp").GetProperty("size").GetString());
    }

    [Fact]
    public async Task ResponseIsStreamedNotBuffered()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop("http://stub.example"));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        var gate = new TaskCompletionSource();
        var pipe = new System.IO.Pipelines.Pipe();
        var stub = new StubHandler((r, ct) =>
        {
            var content = new StreamContent(pipe.Reader.AsStream());
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content, RequestMessage = r });
        });
        using var http = new HttpClient(new TrafficTwinHandler(sut.Agent!, stub));
        using var res = await http.SendAsync(new HttpRequestMessage(HttpMethod.Post, "http://stub.example/v1/shipments") { Content = new StringContent("{}", Encoding.UTF8, "application/json") }, HttpCompletionOption.ResponseHeadersRead);
        await pipe.Writer.WriteAsync(Encoding.UTF8.GetBytes("{\"status\":"));
        using Stream s = await res.Content.ReadAsStreamAsync();
        var buf = new byte[64];
        // The first chunk is available while the producer has not finished: the content was not buffered.
        int n = await s.ReadAsync(buf).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("{\"status\":", Encoding.UTF8.GetString(buf, 0, n));
        await pipe.Writer.WriteAsync(Encoding.UTF8.GetBytes("\"PENDING\"}"));
        await pipe.Writer.CompleteAsync();
        var rest = new MemoryStream();
        await s.CopyToAsync(rest);
        Assert.Equal("\"PENDING\"}", Encoding.UTF8.GetString(rest.ToArray()));
        var ev = (await Outbound(core, sut, 1)).Single();
        Assert.Equal("keep:PENDING", ev.GetProperty("resp").GetProperty("body").GetProperty("status").GetString());
    }

    [Fact]
    public async Task SynchronousSendAndReadAreCaptured()
    {
        await using var carrier = await Carrier.StartAsync();
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(carrier.BaseUrl));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        using var http = new HttpClient(new TrafficTwinHandler(sut.Agent!, new SocketsHttpHandler()));
        var req = new HttpRequestMessage(HttpMethod.Post, carrier.BaseUrl + "/v1/shipments") { Content = new StringContent("{\"orderId\":\"A1\"}", Encoding.UTF8, "application/json") };
        using var res = await Task.Run(() => http.Send(req));
        using var s = res.Content.ReadAsStream();
        string body = new StreamReader(s).ReadToEnd();
        Assert.Contains("SHP-7781203", body);
        var ev = (await Outbound(core, sut, 1)).Single();
        Assert.Equal("keep:PENDING", ev.GetProperty("resp").GetProperty("body").GetProperty("status").GetString());
        Assert.StartsWith("tk1:k1:", ev.GetProperty("req").GetProperty("body").GetProperty("orderId").GetString());
    }

    [Fact]
    public async Task RetriedRequestBodyIsReportedOnce()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop("http://stub.example"));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        // An inner retry handler serializes the same content twice.
        var stub = new StubHandler(async (r, ct) =>
        {
            for (int i = 0; i < 2; i++) await r.Content!.CopyToAsync(Stream.Null, ct);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}", Encoding.UTF8, "application/json"), RequestMessage = r };
        });
        using var http = new HttpClient(new TrafficTwinHandler(sut.Agent!, stub));
        var res = await http.PostAsync("http://stub.example/v1/shipments", new StringContent("{\"orderId\":\"A1\"}", Encoding.UTF8, "application/json"));
        await res.Content.ReadAsStringAsync();
        var ev = (await Outbound(core, sut, 1)).Single();
        Assert.Equal("l32", ev.GetProperty("req").GetProperty("size").GetString());
    }

    [Fact]
    public async Task OriginalRequestContentIsGivenBack()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop("http://stub.example"));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        var stub = new StubHandler((r, ct) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent) { RequestMessage = r }));
        using var http = new HttpClient(new TrafficTwinHandler(sut.Agent!, stub));
        var content = new StringContent("{}", Encoding.UTF8, "application/json");
        var req = new HttpRequestMessage(HttpMethod.Post, "http://stub.example/v1/shipments") { Content = content };
        using var res = await http.SendAsync(req);
        Assert.Same(content, req.Content);
    }

    [Fact]
    public async Task PlainHttpClientIsSeenThroughTheDiagnosticListenerWithoutAnyInjection()
    {
        await using var carrier = await Carrier.StartAsync();
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(carrier.BaseUrl));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        System.Diagnostics.Activity.Current = null;
        using var http = new HttpClient(); // no handler of the SDK
        var res = await http.PostAsync(carrier.BaseUrl + "/v1/shipments", new StringContent("{\"orderId\":\"ORD-2026-000184\"}", Encoding.UTF8, "application/json"));
        await res.Content.ReadAsStringAsync();
        var ev = (await Outbound(core, sut, 1)).Single(e => e.GetProperty("service").GetString() == "shipping-ext");
        Assert.Equal(201, ev.GetProperty("status").GetInt32());
        Assert.Equal("POST /v1/shipments", ev.GetProperty("op").GetString());
        // Bodies are not visible to the listener: reported as not captured.
        Assert.Equal("trunc:size", ev.GetProperty("req").GetProperty("body").GetString());
        Assert.Equal("trunc:size", ev.GetProperty("resp").GetProperty("body").GetString());
        // Subscribing must not make the runtime start an Activity or add traceparent to the app's requests.
        var got = carrier.Requests.Single();
        Assert.DoesNotContain("traceparent", got.Headers.Keys);
        Assert.DoesNotContain("tracestate", got.Headers.Keys);
        Assert.DoesNotContain("baggage", got.Headers.Keys);
    }

    [Fact]
    public async Task RequestsThroughTheHandlerAreNotCountedTwice()
    {
        await using var carrier = await Carrier.StartAsync();
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(carrier.BaseUrl));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        using var http = new HttpClient(new TrafficTwinHandler(sut.Agent!, new SocketsHttpHandler()));
        for (int i = 0; i < 3; i++) await (await http.PostAsync(carrier.BaseUrl + "/v1/shipments", new StringContent("{}", Encoding.UTF8, "application/json"))).Content.ReadAsStringAsync();
        await Task.Delay(300);
        var ev = await Outbound(core, sut, 3);
        await Task.Delay(500);
        ev = await Outbound(core, sut, 3);
        Assert.Equal(3, ev.Count);
    }

    [Fact]
    public async Task SdkOwnTrafficIsNeverCaptured()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        await sut.Client.GetAsync("/health");
        await sut.Agent!.FlushAsync();
        int hb = core.Heartbeats.Count;
        await Wait.UntilAsync(() => core.Heartbeats.Count >= hb + 3, what: "heartbeats");
        await sut.Agent.FlushAsync();
        await Task.Delay(300);
        var events = core.Events.Select(Parse).ToList();
        Assert.DoesNotContain(events, e => e.GetProperty("dir").GetString() == "outbound");
        Assert.Single(events);
    }

    [Fact]
    public async Task ConnectionRefusedIsANetErrorEvent()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop("http://127.0.0.1:9"));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        using var http = new HttpClient(new TrafficTwinHandler(sut.Agent!, new SocketsHttpHandler()));
        await Assert.ThrowsAsync<HttpRequestException>(() => http.GetAsync("http://127.0.0.1:9/v1/shipments"));
        var ev = (await Outbound(core, sut, 1)).Single();
        Assert.Equal("refused", ev.GetProperty("net_error").GetString());
        Assert.False(ev.TryGetProperty("status", out _));
        Assert.False(ev.TryGetProperty("resp", out _));
    }

    [Fact]
    public async Task UnresolvableHostIsADnsError()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        using var http = new HttpClient(new TrafficTwinHandler(sut.Agent!, new SocketsHttpHandler()));
        await Assert.ThrowsAnyAsync<HttpRequestException>(() => http.GetAsync("http://no-such-host.invalid/x"));
        var ev = (await Outbound(core, sut, 1)).Single();
        Assert.Equal("dns", ev.GetProperty("net_error").GetString());
        Assert.Equal("host:no-such-host.invalid", ev.GetProperty("service").GetString());
    }

    [Fact]
    public async Task TimeoutIsATimeoutEvent()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        var stub = new StubHandler(async (r, ct) => { await Task.Delay(Timeout.Infinite, ct); return null!; });
        using var http = new HttpClient(new TrafficTwinHandler(sut.Agent!, stub)) { Timeout = TimeSpan.FromMilliseconds(100) };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => http.GetAsync("http://stub.example/x"));
        var ev = (await Outbound(core, sut, 1)).Single();
        Assert.Equal("timeout", ev.GetProperty("net_error").GetString());
    }

    [Fact]
    public async Task BaggageMemberIsAddedOnlyTowardPropagateToHosts()
    {
        await using var carrier = await Carrier.StartAsync();
        var uri = new Uri(carrier.BaseUrl);
        string hostPort = uri.Host + ":" + uri.Port;
        // The carrier is an internal service listed in propagate_to and not a policy base.
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(propagateTo: new[] { hostPort }));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        using var http = new HttpClient(new TrafficTwinHandler(sut.Agent!, new SocketsHttpHandler()));
        var req = new HttpRequestMessage(HttpMethod.Get, carrier.BaseUrl + "/x");
        req.Headers.TryAddWithoutValidation("baggage", "userId=alice");
        await http.SendAsync(req);
        var got = carrier.Requests.Single();
        Assert.Equal("userId=alice,tt.s=1", got.Headers["baggage"]);
    }

    [Fact]
    public async Task BaggageIsNeverAddedTowardAPolicyBase()
    {
        await using var carrier = await Carrier.StartAsync();
        var uri = new Uri(carrier.BaseUrl);
        string hostPort = uri.Host + ":" + uri.Port;
        var policy = PolicyFactory.Shop(carrier.BaseUrl, propagateTo: new[] { hostPort });
        await using var core = await FakeCore.StartAsync(policy);
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        using var http = new HttpClient(new TrafficTwinHandler(sut.Agent!, new SocketsHttpHandler()));
        await http.GetAsync(carrier.BaseUrl + "/x");
        Assert.DoesNotContain("baggage", carrier.Requests.Single().Headers.Keys);
    }

    [Fact]
    public async Task WithoutAnActiveSanitizerTheHandlerIsAPassThrough()
    {
        await using var carrier = await Carrier.StartAsync();
        var agent = TrafficTwinAgent.Create(new TrafficTwinOptions()); // never started: no policy, no key
        using var http = new HttpClient(new TrafficTwinHandler(agent, new SocketsHttpHandler()));
        var res = await http.PostAsync(carrier.BaseUrl + "/v1/shipments", new StringContent("{\"orderId\":\"A\"}", Encoding.UTF8, "application/json"));
        Assert.Contains("SHP-7781203", await res.Content.ReadAsStringAsync());
        Assert.Equal(0, agent.Status().ExchangesSeen);
        await agent.DisposeAsync();
    }
}
