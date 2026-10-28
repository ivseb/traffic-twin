using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TrafficTwin.Sdk;
using TrafficTwin.Sdk.Sanitizing;
using TrafficTwin.Sdk.Tests.Helpers;

// Overhead benchmark (threat model G10, M12).
//
//   dotnet run -c Release --project bench/TrafficTwin.Bench -- [--seconds 6] [--concurrency 16] [--rounds 2] [--steady-rps 300]
//
// 1. micro:      cost of sanitize + event assembly for one exchange (2 KiB and 64 KiB bodies), in a loop;
// 2. hot path:   time the capture hooks spend on the REQUEST thread (the agent's own overhead_us counter);
// 3. end to end: the same minimal-API app on Kestrel with the SDK off and on (100% and 5% sampling), driven by a load generator
//                in a SEPARATE process (so that the SDK does not capture the load generator's own HttpClient calls):
//                saturation throughput (closed loop) and latency at a fixed request rate (open loop, below saturation).
//                Every POST /orders is one inbound exchange; the SDK exports to a fake tt-core over mTLS in the same process.

internal static class Program
{
    private const string OrderBody = "{\"items\":[{\"sku\":\"TSHIRT-RED-M\",\"qty\":2},{\"sku\":\"MUG-BLUE\",\"qty\":1}],\"email\":\"giulia.neri@example.com\",\"note\":\"leave at the door\"}";

    private static double Arg(string[] a, string name, double d)
    {
        int i = Array.IndexOf(a, "--" + name);
        return i >= 0 && i + 1 < a.Length ? double.Parse(a[i + 1], CultureInfo.InvariantCulture) : d;
    }

    public static async Task<int> Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "client") return await ClientAsync(args);
        Console.WriteLine($".NET {Environment.Version}, {System.Runtime.InteropServices.RuntimeInformation.OSDescription}, {Environment.ProcessorCount} CPUs");
        Micro();
        HotPieces();
        double seconds = Arg(args, "seconds", 6);
        int conc = (int)Arg(args, "concurrency", 16);
        int rounds = (int)Arg(args, "rounds", 2);
        double steady = Arg(args, "steady-rps", 300);
        await EndToEnd(seconds, conc, rounds, steady);
        return 0;
    }

    // --- 1. micro ---------------------------------------------------------------------

    private static (Sanitizer San, Exchange Ex) MakeExchange(int bodyBytes)
    {
        var body = PolicyFactory.Shop();
        body["created_at"] = PolicyFactory.Iso(DateTimeOffset.UtcNow.AddMinutes(-1));
        var policy = new Policy(PolicyChecks.ValidateBodySchema(Plain.From(JsonParser.Parse(PolicyFactory.BodyBytes(body)), true)));
        var ring = PolicyChecks.ParseKeyRing(PolicyFactory.HmacKeyLine);
        var (kid, key) = PolicyChecks.SelectKey(ring, policy);
        var san = new Sanitizer(policy, kid, key);
        var sb = new StringBuilder("{\"items\":[");
        string item = "{\"sku\":\"TSHIRT-RED-M\",\"qty\":2,\"price\":19.9,\"gift\":false,\"tags\":[\"a\",\"b\"]}";
        sb.Append(item);
        while (sb.Length < bodyBytes - 120) sb.Append(',').Append(item);
        sb.Append("],\"email\":\"giulia.neri@example.com\",\"note\":\"leave at the door\"}");
        byte[] reqBody = Encoding.UTF8.GetBytes(sb.ToString());
        var ex = new Exchange
        {
            Inbound = true,
            ServiceName = "shop-api",
            Method = "POST",
            RawPath = Encoding.ASCII.GetBytes("/orders"),
            RawQuery = Encoding.ASCII.GetBytes("promo=AUTUMN10&utm_source=mail"),
            Framework = "aspnetcore",
            FrameworkRoute = "/orders",
            ReqHeaders = new()
            {
                ("Host", Encoding.ASCII.GetBytes("shop.example")), ("Content-Type", Encoding.ASCII.GetBytes("application/json")),
                ("User-Agent", Encoding.ASCII.GetBytes("Mozilla/5.0 (X11; Linux x86_64)")), ("Accept", Encoding.ASCII.GetBytes("*/*")),
                ("Cookie", Encoding.ASCII.GetBytes("sid=9f8e7d6c5b4a; theme=dark")), ("X-Customer", Encoding.ASCII.GetBytes("cust-0042")),
            },
            ReqBody = reqBody,
            ReqBodyTotal = reqBody.Length,
            Status = 201,
            RespHeaders = new() { ("Content-Type", Encoding.ASCII.GetBytes("application/json; charset=utf-8")) },
            RespBody = Encoding.UTF8.GetBytes("{\"id\":\"ORD-2026-000184\",\"status\":\"CREATED\",\"total\":73.40}"),
        };
        ex.RespBodyTotal = ex.RespBody.Length;
        return (san, ex);
    }

    private static void Micro()
    {
        Console.WriteLine("\n[1] sanitize + serialize one exchange (single thread, warmed up)");
        foreach (int size in new[] { 2048, 65536 })
        {
            var (san, ex) = MakeExchange(size);
            double now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            for (int i = 0; i < 3000; i++) san.Run(ex, now);
            var samples = new List<double>();
            for (int batch = 0; batch < 40; batch++)
            {
                int n = size > 10000 ? 40 : 400;
                long t0 = Stopwatch.GetTimestamp();
                for (int i = 0; i < n; i++) san.Run(ex, now);
                samples.Add((Stopwatch.GetTimestamp() - t0) * 1e6 / Stopwatch.Frequency / n);
            }
            samples.Sort();
            Console.WriteLine($"    body {ex.ReqBody!.Length,6} B   p50 {samples[samples.Count / 2],8:F1} us   p90 {samples[(int)(samples.Count * 0.9)],8:F1} us   min {samples[0],8:F1} us");
        }
    }

    private static void HotPieces()
    {
        Console.WriteLine("\n[2] pieces of the request-thread path (ns per call, single thread)");
        var (san, ex) = MakeExchange(2048);
        var hdrs = ex.ReqHeaders;
        static double Time(Action a, int n)
        {
            for (int i = 0; i < n / 10; i++) a();
            long t0 = Stopwatch.GetTimestamp();
            for (int i = 0; i < n; i++) a();
            return (Stopwatch.GetTimestamp() - t0) * 1e9 / Stopwatch.Frequency / n;
        }
        Console.WriteLine($"    Decide (no subject, random)      {Time(() => san.Decide(true, "shop-api", hdrs, null, null), 1_000_000),8:F0} ns");
        var hdrs2 = new List<(string, byte[])> { ("x-customer", Encoding.ASCII.GetBytes("cust-0042")) };
        Console.WriteLine($"    Decide (subject header, HMAC)    {Time(() => san.Decide(true, "shop-api", hdrs2, null, null), 200_000),8:F0} ns");
        Console.WriteLine($"    AsyncLocal set + new context     {Time(() => TrafficTwin.Sdk.Capture.ExchangeContext.Current = new TrafficTwin.Sdk.Capture.ExchangeCtx { TraceId = "x" }, 2_000_000),8:F0} ns");
        Console.WriteLine($"    Stopwatch.GetTimestamp           {Time(() => Stopwatch.GetTimestamp(), 5_000_000),8:F0} ns");
        Console.WriteLine($"    new TraceId (CSPRNG 16 B)        {Time(() => TrafficTwin.Sdk.Capture.ExchangeContext.NewTraceId(), 500_000),8:F0} ns");
    }

    // --- 3. end to end -------------------------------------------------------------------

    private sealed record Result(double Rps, double P50Ms, double P99Ms, double CpuUsPerReq);

    private static async Task<int> ClientAsync(string[] a)
    {
        // client <url> <mode: sat|steady> <seconds> <concurrency|rps>
        string url = a[1];
        string mode = a[2];
        double seconds = double.Parse(a[3], CultureInfo.InvariantCulture);
        double param = double.Parse(a[4], CultureInfo.InvariantCulture);
        using var http = new HttpClient(new SocketsHttpHandler { MaxConnectionsPerServer = 64, PooledConnectionLifetime = TimeSpan.FromMinutes(10) });
        var lat = new List<double>();
        var gate = new object();
        async Task One()
        {
            long t0 = Stopwatch.GetTimestamp();
            using var res = await http.PostAsync(url + "/orders", new StringContent(OrderBody, Encoding.UTF8, "application/json"));
            await res.Content.ReadAsByteArrayAsync();
            double ms = (Stopwatch.GetTimestamp() - t0) * 1000.0 / Stopwatch.Frequency;
            lock (gate) lat.Add(ms);
        }
        for (int i = 0; i < 300; i++) await One(); // warm up
        lat.Clear();
        var sw = Stopwatch.StartNew();
        if (mode == "sat")
        {
            var workers = Enumerable.Range(0, (int)param).Select(async _ => { while (sw.Elapsed.TotalSeconds < seconds) await One(); });
            await Task.WhenAll(workers);
        }
        else
        {
            var tasks = new List<Task>();
            double interval = 1000.0 / param;
            long next = 0;
            while (sw.Elapsed.TotalSeconds < seconds)
            {
                if (sw.ElapsedMilliseconds >= next) { tasks.Add(One()); next += (long)interval; }
                else await Task.Delay(1);
            }
            await Task.WhenAll(tasks);
        }
        double elapsed = sw.Elapsed.TotalSeconds;
        lat.Sort();
        Console.WriteLine(string.Join(" ", lat.Count / elapsed, lat[lat.Count / 2], lat[(int)(lat.Count * 0.99)]).Replace(',', '.'));
        return 0;
    }

    private static async Task<(double Rps, double P50, double P99)> RunClient(string url, string mode, double seconds, double param)
    {
        var psi = new ProcessStartInfo("dotnet", $"\"{typeof(Program).Assembly.Location}\" client {url} {mode} {seconds.ToString(CultureInfo.InvariantCulture)} {param.ToString(CultureInfo.InvariantCulture)}")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        using var p = Process.Start(psi)!;
        string outp = await p.StandardOutput.ReadToEndAsync();
        await p.WaitForExitAsync();
        var f = outp.Trim().Split('\n').Last().Split(' ').Select(x => double.Parse(x, CultureInfo.InvariantCulture)).ToArray();
        return (f[0], f[1], f[2]);
    }

    private static async Task EndToEnd(double seconds, int conc, int rounds, double steadyRps)
    {
        Console.WriteLine($"\n[3] end to end, minimal API on Kestrel, load generator in another process ({seconds}s per measure, {rounds} rounds)");
        var modes = new (string Name, bool Sdk, long Bp)[] { ("sdk off", false, 0), ("sdk on, 100% sampled", true, 10000), ("sdk on, 5% sampled", true, 500) };
        var sat = modes.ToDictionary(m => m.Name, _ => new List<(double Rps, double P50, double P99)>());
        var steady = modes.ToDictionary(m => m.Name, _ => new List<(double Rps, double P50, double P99)>());
        var hot = new Dictionary<string, (long P50, long P99)>();
        for (int round = 0; round < rounds; round++)
        {
            foreach (var m in modes)
            {
                FakeCore? core = m.Sdk ? await FakeCore.StartAsync(PolicyFactory.Shop(rateBp: m.Bp)) : null;
                await using var sut = await Sut.StartAsync(new SutOptions { UseKestrel = true, Sdk = m.Sdk, Core = core, Heartbeat = TimeSpan.FromSeconds(30), PolicyPoll = TimeSpan.FromSeconds(30), Flush = TimeSpan.FromSeconds(1) });
                if (m.Sdk) await sut.WaitCapturingAsync();
                string url = sut.Client.BaseAddress!.ToString().TrimEnd('/');
                sat[m.Name].Add(await RunClient(url, "sat", seconds, conc));
                steady[m.Name].Add(await RunClient(url, "steady", seconds, steadyRps));
                if (m.Sdk)
                {
                    hot[m.Name] = sut.Agent!.OverheadUs();
                    var st = sut.Agent.Status();
                    await sut.Agent.FlushAsync();
                    Console.WriteLine($"    round {round + 1} {m.Name,-22}: exchanges seen {st.ExchangesSeen}, sampled {st.ExchangesSampled}, events dropped (queue) {st.EventsDroppedQueue}, sanitizer errors {st.SanitizerErrors}");
                }
                if (core != null) await core.DisposeAsync();
            }
        }
        static double Med(IEnumerable<double> v) { var a = v.OrderBy(x => x).ToList(); return a[a.Count / 2]; }
        Console.WriteLine($"\n    saturation ({conc} connections, closed loop)                 req/s    p50 ms   p99 ms");
        double baseRps = Med(sat["sdk off"].Select(x => x.Rps));
        foreach (var m in modes)
        {
            double rps = Med(sat[m.Name].Select(x => x.Rps));
            Console.WriteLine($"    {m.Name,-30}                {rps,9:F0}  {Med(sat[m.Name].Select(x => x.P50)),8:F2} {Med(sat[m.Name].Select(x => x.P99)),8:F2}   ({(rps / baseRps - 1) * 100:+0.0;-0.0}% throughput)");
        }
        Console.WriteLine($"\n    steady ({steadyRps:F0} req/s, open loop)                         req/s    p50 ms   p99 ms");
        double baseP50 = Med(steady["sdk off"].Select(x => x.P50));
        foreach (var m in modes)
        {
            double p50 = Med(steady[m.Name].Select(x => x.P50));
            Console.WriteLine($"    {m.Name,-30}                {Med(steady[m.Name].Select(x => x.Rps)),9:F0}  {p50,8:F2} {Med(steady[m.Name].Select(x => x.P99)),8:F2}   (p50 {p50 - baseP50:+0.000;-0.000} ms)");
        }
        Console.WriteLine("\n    request-thread time of the hooks (agent overhead_us, last 1024 exchanges)");
        foreach (var kv in hot) Console.WriteLine($"    {kv.Key,-30}: p50 {kv.Value.P50} us, p99 {kv.Value.P99} us");
    }
}
