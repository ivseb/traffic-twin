using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TrafficTwin.Sdk.AspNetCore;

namespace TrafficTwin.Sdk.Tests.Helpers;

/// <summary>A tiny "carrier" API on Kestrel (plain HTTP) that records what it receives. Invented data.</summary>
internal sealed class Carrier : IAsyncDisposable
{
    public string BaseUrl { get; private set; } = "";
    public ConcurrentQueue<(string Method, string Path, Dictionary<string, string> Headers, string Body)> Requests { get; } = new();
    private WebApplication app = null!;

    public static async Task<Carrier> StartAsync()
    {
        var c = new Carrier();
        var b = WebApplication.CreateBuilder();
        b.Logging.ClearProviders();
        b.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0));
        c.app = b.Build();
        c.app.Run(async ctx =>
        {
            using var sr = new StreamReader(ctx.Request.Body, Encoding.UTF8);
            string body = await sr.ReadToEndAsync();
            var headers = ctx.Request.Headers.ToDictionary(h => h.Key.ToLowerInvariant(), h => h.Value.ToString());
            c.Requests.Enqueue((ctx.Request.Method, ctx.Request.Path + ctx.Request.QueryString, headers, body));
            if (ctx.Request.Path.StartsWithSegments("/v1/shipments") && ctx.Request.Method == "POST")
            {
                ctx.Response.StatusCode = 201;
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync("{\"shipmentId\":\"SHP-7781203\",\"status\":\"PENDING\",\"recipient\":\"Giulia Neri\"}");
                return;
            }
            if (ctx.Request.Path.StartsWithSegments("/boom"))
            {
                ctx.Response.StatusCode = 422;
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync("{\"error\":{\"code\":\"ADDRESS_INVALID\",\"detail\":\"Via Roma 1, Milano\"}}");
                return;
            }
            ctx.Response.StatusCode = 404;
        });
        await c.app.StartAsync();
        c.BaseUrl = c.app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        return c;
    }

    public async ValueTask DisposeAsync()
    {
        await app.StopAsync();
        await app.DisposeAsync();
    }
}

internal sealed class SutOptions
{
    public bool UseKestrel;
    public bool Sdk = true;
    public string? HmacKey = PolicyFactory.HmacKeyLine;
    public string? StateDir;
    public string ServiceName = "shop-api";
    public Carrier? Carrier;
    public TimeSpan Heartbeat = TimeSpan.FromMilliseconds(300);
    public TimeSpan PolicyPoll = TimeSpan.FromMilliseconds(300);
    public TimeSpan Flush = TimeSpan.FromMilliseconds(100);
    public Action<IServiceCollection>? Services;
    public Action<WebApplication>? PreMiddleware;
    public Action<WebApplication>? Endpoints;
    public FakeCore? Core;
    public bool UseCsr = true;
}

/// <summary>The application under test: minimal APIs on TestServer or on Kestrel, with or without the SDK.</summary>
internal sealed class Sut : IAsyncDisposable
{
    public WebApplication App { get; private set; } = null!;
    public HttpClient Client { get; private set; } = null!;
    public TrafficTwinAgent? Agent { get; private set; }
    public string StateDir { get; }
    private readonly bool deleteStateDir;

    private Sut(string stateDir, bool delete)
    {
        StateDir = stateDir;
        deleteStateDir = delete;
    }

    public static async Task<Sut> StartAsync(SutOptions o)
    {
        string dir = o.StateDir ?? Path.Combine(Path.GetTempPath(), "tt-test-" + Guid.NewGuid().ToString("N"));
        var sut = new Sut(dir, o.StateDir == null);
        var b = WebApplication.CreateBuilder();
        b.Logging.ClearProviders();
        if (o.UseKestrel) b.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0));
        else b.WebHost.UseTestServer();
        b.Services.AddHttpClient("carrier");
        if (o.Sdk)
        {
            b.Services.AddTrafficTwin(opt =>
            {
                opt.EnrollUrl = o.Core!.BaseUrl;
                opt.EnrollToken = o.Core.Token;
                opt.HmacKey = o.HmacKey;
                opt.ServiceName = o.ServiceName;
                opt.StateDir = dir;
                opt.UseCsr = o.UseCsr;
                opt.HeartbeatInterval = o.Heartbeat;
                opt.PolicyPollInterval = o.PolicyPoll;
                opt.ExportFlushInterval = o.Flush;
            });
        }
        o.Services?.Invoke(b.Services);
        WebApplication app = b.Build();
        sut.App = app;
        o.PreMiddleware?.Invoke(app);
        if (o.Sdk) app.UseTrafficTwin();
        MapApp(app, o.Carrier?.BaseUrl);
        o.Endpoints?.Invoke(app);
        await app.StartAsync();
        if (o.UseKestrel)
        {
            string addr = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
            sut.Client = new HttpClient { BaseAddress = new Uri(addr) };
        }
        else sut.Client = app.GetTestClient();
        if (o.Sdk) sut.Agent = app.Services.GetRequiredService<TrafficTwinAgent>();
        return sut;
    }

    private static void MapApp(WebApplication app, string? carrierBase)
    {
        app.MapPost("/orders", async (HttpContext ctx, IHttpClientFactory f) =>
        {
            using var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
            string email = doc.RootElement.TryGetProperty("email", out var e) ? e.GetString() ?? "" : "";
            string shipmentId = "";
            if (carrierBase != null)
            {
                var http = f.CreateClient("carrier");
                var res = await http.PostAsync(carrierBase + "/v1/shipments", new StringContent("{\"orderId\":\"ORD-2026-000184\",\"to\":\"" + email + "\"}", Encoding.UTF8, "application/json"));
                using var rd = JsonDocument.Parse(await res.Content.ReadAsStringAsync());
                shipmentId = rd.RootElement.GetProperty("shipmentId").GetString() ?? "";
            }
            ctx.Response.StatusCode = 201;
            return Results.Json(new { id = "ORD-2026-000184", status = "CREATED", total = 73.40, shipmentId, note = "ciao Giulia" }, statusCode: 201);
        });
        app.MapGet("/orders/{id}", (string id) => Results.Json(new { id, status = "SHIPPED" }));
        app.MapGet("/health", () => "ok");
        app.MapGet("/echo", (HttpContext ctx) => Results.Text("echo:" + ctx.Request.QueryString.Value));
        app.MapPost("/upload", async (HttpContext ctx) =>
        {
            long n = 0;
            var buf = new byte[4096];
            int r;
            while ((r = await ctx.Request.Body.ReadAsync(buf)) > 0) n += r;
            return Results.Text(n.ToString());
        });
        app.MapGet("/stream", async (HttpContext ctx) =>
        {
            ctx.Response.ContentType = "text/plain";
            for (int i = 0; i < 3; i++)
            {
                await ctx.Response.WriteAsync("chunk" + i + "\n");
                await ctx.Response.Body.FlushAsync();
            }
        });
        app.MapGet("/boom-carrier", async (IHttpClientFactory f) =>
        {
            var http = f.CreateClient("carrier");
            var res = await http.GetAsync(carrierBase + "/boom");
            return Results.Text(((int)res.StatusCode).ToString());
        });
        app.MapGet("/fail", (HttpContext _) => Results.StatusCode(503));
    }

    public async Task WaitCapturingAsync(int timeoutMs = 20000)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs && Agent!.State != "capturing") await Task.Delay(20);
        if (Agent!.State != "capturing") throw new TimeoutException("agent state is " + Agent.State);
    }

    public async Task WaitStateAsync(string state, int timeoutMs = 20000)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs && Agent!.State != state) await Task.Delay(20);
        if (Agent!.State != state) throw new TimeoutException("agent state is " + Agent.State + ", expected " + state);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await App.StopAsync();
        await App.DisposeAsync();
        if (Agent != null) await Agent.DisposeAsync();
        if (deleteStateDir)
        {
            try { Directory.Delete(StateDir, true); }
            catch (Exception) { /* best effort */ }
        }
    }
}

internal static class Wait
{
    public static async Task UntilAsync(Func<bool> cond, int timeoutMs = 15000, string? what = null)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            if (cond()) return;
            await Task.Delay(20);
        }
        if (!cond()) throw new TimeoutException("timed out waiting for " + (what ?? "condition"));
    }
}
