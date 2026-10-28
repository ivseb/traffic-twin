using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using TrafficTwin.Sdk.Tests.Helpers;
using Xunit;

namespace TrafficTwin.Sdk.Tests;

/// <summary>
/// Zero-code injection. The application under test (<c>TrafficTwin.TestApp</c>) references nothing of traffic-twin; the SDK reaches it
/// from outside: the hosting startup assembly (<c>ASPNETCORE_HOSTINGSTARTUPASSEMBLIES</c>), which on a real process is found through
/// the <c>DOTNET_STARTUP_HOOKS</c> assembly.
/// </summary>
public class ZeroCodeTests
{
    private const string OrderBody = "{\"items\":[{\"sku\":\"TSHIRT-RED-M\",\"qty\":2}],\"email\":\"giulia.neri@example.com\",\"note\":\"citofono Neri\"}";
    private static readonly string[] Secrets = { "giulia", "Giulia", "Neri", "ORD-2026-000184", "SHP-7781203", "TSHIRT-RED-M", "citofono" };

    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement.Clone();

    private static Dictionary<string, string?> TtEnv(FakeCore core, string stateDir, string carrierUrl) => new()
    {
        ["TT_ENROLL_URL"] = core.BaseUrl,
        ["TT_ENROLL_TOKEN"] = core.Token,
        ["TT_HMAC_KEY"] = PolicyFactory.HmacKeyLine,
        ["TT_SERVICE_NAME"] = "shop-api",
        ["TT_STATE_DIR"] = stateDir,
        ["TT_HEARTBEAT_INTERVAL_MS"] = "300",
        ["TT_POLICY_POLL_INTERVAL_MS"] = "300",
        ["TT_EXPORT_FLUSH_MS"] = "100",
        ["CARRIER_URL"] = carrierUrl,
    };

    private static void AssertEvents(FakeCore core, IReadOnlyList<string> raw, bool withPlain)
    {
        var events = raw.Select(Parse).ToList();
        var inbound = events.Single(e => e.GetProperty("dir").GetString() == "inbound" && e.GetProperty("op").GetString() == "POST /orders");
        var shipments = events.Where(e => e.GetProperty("dir").GetString() == "outbound" && e.GetProperty("op").GetString() == "POST /v1/shipments").ToList();
        var factory = shipments.Single(e => e.GetProperty("req").GetProperty("body").ValueKind == JsonValueKind.Object);
        Assert.Equal("shop-api", inbound.GetProperty("service").GetString());
        Assert.Equal("framework", inbound.GetProperty("route_source").GetString());
        Assert.Equal(201, inbound.GetProperty("status").GetInt32());
        Assert.Equal("drop:str:email", inbound.GetProperty("req").GetProperty("body").GetProperty("email").GetString());
        Assert.StartsWith("tk1:k1:", inbound.GetProperty("resp").GetProperty("body").GetProperty("id").GetString());
        Assert.Equal("inherited", factory.GetProperty("sampled_by").GetString());
        Assert.Equal(inbound.GetProperty("trace_id").GetString(), factory.GetProperty("trace_id").GetString());
        Assert.Equal(inbound.GetProperty("span_id").GetString(), factory.GetProperty("parent_span_id").GetString());
        // The factory client goes through TrafficTwinHandler: bodies are captured.
        Assert.StartsWith("tk1:k1:", factory.GetProperty("req").GetProperty("body").GetProperty("orderId").GetString());
        if (withPlain)
        {
            var plain = shipments.Single(e => e.GetProperty("req").GetProperty("body").ValueKind == JsonValueKind.String);
            // A plain `new HttpClient()` is seen through the diagnostics listener: metadata, the body is not visible.
            Assert.Equal("trunc:size", plain.GetProperty("req").GetProperty("body").GetString());
            Assert.Equal(201, plain.GetProperty("status").GetInt32());
        }
        string all = string.Join("\n", core.OtlpRequests);
        foreach (string s in Secrets) Assert.DoesNotContain(s, all);
    }

    // --- WebApplicationFactory: the hosting startup alone ------------------------------------------------

    private sealed class TestAppFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseSetting(WebHostDefaults.HostingStartupAssembliesKey, "TrafficTwin.Sdk.AspNetCore");
        }
    }

    [Fact]
    public async Task HostingStartup_RegistersMiddlewareAndFactoryHandlerWithoutCodeChanges()
    {
        await using var carrier = await Carrier.StartAsync();
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(carrier.BaseUrl));
        string state = Path.Combine(Path.GetTempPath(), "tt-zc-" + Guid.NewGuid().ToString("N"));
        var saved = new Dictionary<string, string?>();
        foreach (var kv in TtEnv(core, state, carrier.BaseUrl))
        {
            saved[kv.Key] = Environment.GetEnvironmentVariable(kv.Key);
            Environment.SetEnvironmentVariable(kv.Key, kv.Value);
        }
        try
        {
            using var factory = new TestAppFactory();
            using HttpClient client = factory.CreateClient(); // builds the host: the hosting startup runs and starts the agent
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < 20000 && TrafficTwinAgent.Current?.State != "capturing") await Task.Delay(20);
            Assert.Equal("capturing", TrafficTwinAgent.Current?.State);

            var res = await client.PostAsync("/orders?promo=AUTUMN10", new StringContent(OrderBody, Encoding.UTF8, "application/json"));
            Assert.Equal(System.Net.HttpStatusCode.Created, res.StatusCode);
            Assert.Contains("\"carrierAnswered\":true", await res.Content.ReadAsStringAsync());

            await TrafficTwinAgent.Current!.FlushAsync();
            AssertEvents(core, await core.WaitEventsAsync(2), withPlain: false);
        }
        finally
        {
            await TrafficTwinAgent.StopCurrentAsync();
            foreach (var kv in saved) Environment.SetEnvironmentVariable(kv.Key, kv.Value);
            try { Directory.Delete(state, true); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task HostingStartup_DoesNothingWithoutEnrollUrl()
    {
        string? saved = Environment.GetEnvironmentVariable("TT_ENROLL_URL");
        Environment.SetEnvironmentVariable("TT_ENROLL_URL", null);
        try
        {
            using var factory = new TestAppFactory();
            using HttpClient client = factory.CreateClient();
            var res = await client.GetAsync("/health");
            Assert.Equal(System.Net.HttpStatusCode.OK, res.StatusCode);
            Assert.Null(TrafficTwinAgent.Current);
        }
        finally
        {
            Environment.SetEnvironmentVariable("TT_ENROLL_URL", saved);
        }
    }

    // --- a real Kestrel process started with the environment variables only -----------------------------------

    private static string Fixture(string name)
    {
        string dir = Path.Combine(AppContext.BaseDirectory, name);
        Assert.True(Directory.Exists(dir), dir + " is published by the test project build");
        return dir;
    }

    private sealed class AppProcess : IAsyncDisposable
    {
        public Process Process = null!;
        public string Url = "";
        public readonly List<string> Output = new();

        public static async Task<AppProcess> StartAsync(Dictionary<string, string?> env, bool withHook)
        {
            string app = Path.Combine(Fixture("testapp"), "TrafficTwin.TestApp.dll");
            var psi = new ProcessStartInfo("dotnet", "\"" + app + "\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                WorkingDirectory = Fixture("testapp"),
            };
            foreach (string k in psi.Environment.Keys.Where(k => k.StartsWith("TT_", StringComparison.Ordinal) || k.StartsWith("DOTNET_STARTUP", StringComparison.Ordinal) || k.StartsWith("ASPNETCORE_", StringComparison.Ordinal)).ToList())
                psi.Environment.Remove(k);
            psi.Environment["ASPNETCORE_URLS"] = "http://127.0.0.1:0";
            psi.Environment["DOTNET_NOLOGO"] = "1";
            if (withHook)
            {
                // TT_TEST_HOOK_DIR: run the same test against another build of the folder (the init image content).
                psi.Environment["DOTNET_STARTUP_HOOKS"] = Path.Combine(Environment.GetEnvironmentVariable("TT_TEST_HOOK_DIR") ?? Fixture("hook"), "TrafficTwin.StartupHook.dll");
                psi.Environment["ASPNETCORE_HOSTINGSTARTUPASSEMBLIES"] = "TrafficTwin.Sdk.AspNetCore";
            }
            foreach (var kv in env) if (kv.Value != null) psi.Environment[kv.Key] = kv.Value;
            var p = new AppProcess { Process = Process.Start(psi)! };
            var listening = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            void OnLine(string? l)
            {
                if (l == null) return;
                lock (p.Output) p.Output.Add(l);
                int i = l.IndexOf("Now listening on: ", StringComparison.Ordinal);
                if (i >= 0) listening.TrySetResult(l.Substring(i + "Now listening on: ".Length).Trim());
            }
            p.Process.OutputDataReceived += (_, e) => OnLine(e.Data);
            p.Process.ErrorDataReceived += (_, e) => OnLine(e.Data);
            p.Process.BeginOutputReadLine();
            p.Process.BeginErrorReadLine();
            Task done = await Task.WhenAny(listening.Task, Task.Delay(60000));
            if (done != listening.Task) throw new TimeoutException("the application did not start:\n" + string.Join("\n", p.Output));
            p.Url = listening.Task.Result;
            return p;
        }

        public ValueTask DisposeAsync()
        {
            try { Process.Kill(true); } catch (InvalidOperationException) { }
            Process.Dispose();
            return ValueTask.CompletedTask;
        }
    }

    [Fact]
    public async Task StartupHookAndHostingStartup_InjectIntoARealKestrelProcess()
    {
        // The application folder contains no trace of traffic-twin: that is the point.
        string appDir = Fixture("testapp");
        Assert.Empty(Directory.GetFiles(appDir, "TrafficTwin.Sdk*"));
        Assert.DoesNotContain("TrafficTwin.Sdk", File.ReadAllText(Path.Combine(appDir, "TrafficTwin.TestApp.deps.json")));

        await using var carrier = await Carrier.StartAsync();
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(carrier.BaseUrl));
        string state = Path.Combine(Path.GetTempPath(), "tt-zc-" + Guid.NewGuid().ToString("N"));
        await using var app = await AppProcess.StartAsync(TtEnv(core, state, carrier.BaseUrl), withHook: true);
        try
        {
            using var http = new HttpClient { BaseAddress = new Uri(app.Url) };
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < 30000 && core.Heartbeats.IsEmpty) await Task.Delay(50);
            Assert.False(core.Heartbeats.IsEmpty, "the injected SDK never reached tt-core:\n" + string.Join("\n", app.Output));
            await Task.Delay(1000); // first policy poll

            var res = await http.PostAsync("/orders?promo=AUTUMN10", new StringContent(OrderBody, Encoding.UTF8, "application/json"));
            Assert.Equal(System.Net.HttpStatusCode.Created, res.StatusCode);
            Assert.Contains("\"carrierAnswered\":true", await res.Content.ReadAsStringAsync());
            Assert.Equal("201", await http.GetStringAsync("/plain"));

            var events = await core.WaitEventsAsync(4, 20000);
            Assert.True(events.Count >= 4, "events: " + events.Count + "\n" + string.Join("\n", app.Output));
            AssertEvents(core, events, withPlain: true);

            // The carrier saw the calls untouched: no traceparent injected, no baggage.
            foreach (var r in carrier.Requests)
            {
                Assert.False(r.Headers.ContainsKey("traceparent"), "traceparent injected: " + r.Method + " " + r.Path + " " + string.Join(";", r.Headers.Select(h => h.Key + "=" + h.Value)));
                Assert.False(r.Headers.ContainsKey("baggage"), "baggage injected");
            }
        }
        finally
        {
            try { Directory.Delete(state, true); } catch (IOException) { }
        }
    }

    [Theory]
    [InlineData("no-url")]
    [InlineData("disabled")]
    public async Task StartupHook_IsInertWithoutEnrollUrlOrWhenDisabled(string mode)
    {
        await using var carrier = await Carrier.StartAsync();
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(carrier.BaseUrl));
        var env = TtEnv(core, Path.Combine(Path.GetTempPath(), "tt-zc-" + Guid.NewGuid().ToString("N")), carrier.BaseUrl);
        if (mode == "no-url") env.Remove("TT_ENROLL_URL");
        else env["TT_DISABLED"] = "1";
        await using var app = await AppProcess.StartAsync(env, withHook: true);
        using var http = new HttpClient { BaseAddress = new Uri(app.Url) };
        var res = await http.PostAsync("/orders", new StringContent(OrderBody, Encoding.UTF8, "application/json"));
        Assert.Equal(System.Net.HttpStatusCode.Created, res.StatusCode);
        await Task.Delay(1500);
        Assert.True(core.Enrollments.IsEmpty);
        Assert.Empty(core.Events);
    }

    [Fact]
    public async Task WithoutTheInjectionTheApplicationIsUntouched()
    {
        await using var carrier = await Carrier.StartAsync();
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(carrier.BaseUrl));
        await using var app = await AppProcess.StartAsync(TtEnv(core, Path.Combine(Path.GetTempPath(), "tt-zc-" + Guid.NewGuid().ToString("N")), carrier.BaseUrl), withHook: false);
        using var http = new HttpClient { BaseAddress = new Uri(app.Url) };
        var res = await http.PostAsync("/orders", new StringContent(OrderBody, Encoding.UTF8, "application/json"));
        Assert.Equal(System.Net.HttpStatusCode.Created, res.StatusCode);
        await Task.Delay(1000);
        Assert.True(core.Enrollments.IsEmpty);
    }
}
