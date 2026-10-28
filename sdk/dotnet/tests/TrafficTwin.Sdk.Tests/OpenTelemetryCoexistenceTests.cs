using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using OpenTelemetry;
using OpenTelemetry.Trace;
using TrafficTwin.Sdk.Tests.Helpers;
using Xunit;

namespace TrafficTwin.Sdk.Tests;

/// <summary>
/// ARCHITECTURE 3.2: the SDK coexists with the OpenTelemetry .NET SDK. It only READS Activity.Current: no TracerProvider, no
/// ActivityListener, no ActivitySource of its own, no propagator, no traceparent injection. The OpenTelemetry packages are
/// referenced by the TESTS only.
/// </summary>
public class OpenTelemetryCoexistenceTests
{
    private sealed record Span(string Name, ActivityKind Kind, string? ParentName, List<string> TagKeys, Dictionary<string, string?> StableTags, string TraceId, string SpanId, string? ParentSpanId);

    private static readonly string[] StableKeys = { "http.request.method", "http.response.status_code", "http.route", "url.path", "url.scheme", "http.method", "http.status_code", "http.target", "http.scheme" };

    private sealed record Run(List<Span> Spans, HashSet<string> Sources, Dictionary<string, string> CarrierHeaders, FakeCore? Core, List<JsonElement> Events);

    private static async Task<Run> ExecuteAsync(bool withSdk)
    {
        var exported = new List<Activity>();
        var started = new ConcurrentBag<string>();
        // Every ActivitySource of the process, to prove the SDK adds none and creates no activity.
        using var all = new ActivityListener
        {
            ShouldListenTo = src => { started.Add(src.Name); return false; },
        };
        ActivitySource.AddActivityListener(all);

        await using var carrier = await Carrier.StartAsync();
        FakeCore? core = withSdk ? await FakeCore.StartAsync(PolicyFactory.Shop(carrier.BaseUrl)) : null;
        try
        {
            await using var sut = await Sut.StartAsync(new SutOptions
            {
                UseKestrel = true,
                Sdk = withSdk,
                Core = core,
                Carrier = carrier,
                Services = s => s.AddOpenTelemetry().WithTracing(t => t
                    .AddAspNetCoreInstrumentation()
                    .AddHttpClientInstrumentation()
                    .AddInMemoryExporter(exported)),
            });
            if (withSdk) await sut.WaitCapturingAsync();
            for (int i = 0; i < 3; i++)
            {
                var res = await sut.Client.PostAsync("/orders", new StringContent("{\"email\":\"giulia.neri@example.com\"}", Encoding.UTF8, "application/json"));
                Assert.Equal(System.Net.HttpStatusCode.Created, res.StatusCode);
            }
            sut.App.Services.GetRequiredService<TracerProvider>().ForceFlush(10000);
            var events = new List<JsonElement>();
            if (withSdk)
            {
                await sut.Agent!.FlushAsync();
                await core!.WaitEventsAsync(6);
                events = core.Events.Select(e => JsonDocument.Parse(e).RootElement.Clone()).ToList();
            }
            var spans = exported.Select(a => new Span(
                a.DisplayName, a.Kind, exported.FirstOrDefault(p => p.SpanId == a.ParentSpanId)?.DisplayName,
                a.TagObjects.Select(t => t.Key).OrderBy(k => k, StringComparer.Ordinal).ToList(),
                a.TagObjects.Where(t => StableKeys.Contains(t.Key)).ToDictionary(t => t.Key, t => t.Value?.ToString()),
                a.TraceId.ToHexString(), a.SpanId.ToHexString(), a.ParentSpanId == default ? null : a.ParentSpanId.ToHexString())).ToList();
            // Keep the traces of the app's own requests (the instrumentation also records the SDK's heartbeat and export calls and the fake core's server side).
            var appTraces = spans.Where(sp => sp.Kind == ActivityKind.Server && sp.StableTags.GetValueOrDefault("url.path") == "/orders").Select(sp => sp.TraceId).ToHashSet();
            spans = spans.Where(sp => appTraces.Contains(sp.TraceId)).ToList();
            var headers = carrier.Requests.Last().Headers;
            return new Run(spans, new HashSet<string>(started), headers, core, events);
        }
        finally
        {
            if (core != null) await core.DisposeAsync();
        }
    }

    private static string Shape(Span s) =>
        s.Name + "|" + s.Kind + "|" + (s.ParentName ?? "-") + "|" + string.Join(",", s.TagKeys) + "|" +
        string.Join(",", s.StableTags.OrderBy(k => k.Key, StringComparer.Ordinal).Select(k => k.Key + "=" + k.Value));

    [Fact]
    public async Task TheAppsSpansAreIdenticalWithAndWithoutTheSdk()
    {
        Run off = await ExecuteAsync(withSdk: false);
        Run on = await ExecuteAsync(withSdk: true);

        // 3 requests x (test client span + app server span + app client span for the carrier call + the carrier's own server span, same process).
        Assert.Equal(12, off.Spans.Count);
        Assert.Equal(off.Spans.Count, on.Spans.Count);
        Assert.Equal(off.Spans.Select(Shape).OrderBy(x => x, StringComparer.Ordinal), on.Spans.Select(Shape).OrderBy(x => x, StringComparer.Ordinal));
        // Same activity sources existed: the SDK created none.
        Assert.True(off.Sources.SetEquals(on.Sources), "sources differ: " + string.Join(",", off.Sources.Except(on.Sources).Concat(on.Sources.Except(off.Sources))));
        Assert.DoesNotContain(on.Sources, n => n.Contains("traffic", StringComparison.OrdinalIgnoreCase));
        // The traceparent seen by the carrier is the app's own (OpenTelemetry's HttpClient instrumentation), in both runs, with the app's span ids.
        Assert.Contains("traceparent", off.CarrierHeaders.Keys);
        Assert.Contains("traceparent", on.CarrierHeaders.Keys);
        Assert.Contains(on.Spans, s => s.Kind == ActivityKind.Client && on.CarrierHeaders["traceparent"] == $"00-{s.TraceId}-{s.SpanId}-01");
        Assert.DoesNotContain("baggage", on.CarrierHeaders.Keys);
    }

    [Fact]
    public async Task EventsReadTheAmbientActivityIdsWithoutCreatingSpans()
    {
        Run on = await ExecuteAsync(withSdk: true);
        var servers = on.Spans.Where(s => s.Kind == ActivityKind.Server && s.StableTags.GetValueOrDefault("url.path") == "/orders").ToList();
        Assert.Equal(3, servers.Count);
        var inbound = on.Events.Where(e => e.GetProperty("dir").GetString() == "inbound").ToList();
        var outbound = on.Events.Where(e => e.GetProperty("dir").GetString() == "outbound" && e.GetProperty("service").GetString() == "shipping-ext").ToList();
        Assert.Equal(3, inbound.Count);
        Assert.Equal(3, outbound.Count);
        foreach (var s in servers)
        {
            // The event IS the server span's view: same trace id, same span id; no span of ours in between.
            var ev = inbound.Single(e => e.GetProperty("trace_id").GetString() == s.TraceId);
            Assert.Equal(s.SpanId, ev.GetProperty("span_id").GetString());
            var o = outbound.Single(e => e.GetProperty("trace_id").GetString() == s.TraceId);
            Assert.Equal(s.SpanId, o.GetProperty("parent_span_id").GetString());
        }
    }

    [Fact]
    public void SdkAssembliesReferenceNothingBeyondTheFramework()
    {
        foreach (var asm in new[] { typeof(TrafficTwinAgent).Assembly, typeof(AspNetCore.TrafficTwinMiddleware).Assembly })
        {
            foreach (var r in asm.GetReferencedAssemblies())
            {
                string n = r.Name!;
                bool ok = n == "netstandard" || n == "mscorlib" || n.StartsWith("System", StringComparison.Ordinal) ||
                          n.StartsWith("Microsoft.AspNetCore", StringComparison.Ordinal) || n.StartsWith("Microsoft.Extensions", StringComparison.Ordinal) ||
                          n == "TrafficTwin.Sdk" || n == "Microsoft.Net.Http.Headers" || n == "Microsoft.Win32.Primitives";
                Assert.True(ok, asm.GetName().Name + " references " + n);
                Assert.DoesNotContain("OpenTelemetry", n);
            }
        }
    }
}
