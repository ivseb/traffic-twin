using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using TrafficTwin.Sdk.Capture;
using TrafficTwin.Sdk.Sanitizing;

namespace TrafficTwin.Sdk.AspNetCore;

/// <summary>
/// Inbound capture for ASP.NET Core. Register it FIRST (<c>app.UseTrafficTwin()</c>) so it sees what is sent on the wire.
///
/// It never alters the traffic: for the exchanges that are sampled it replaces <c>Request.Body</c> and <c>Response.Body</c> with
/// pass-through streams that copy the bytes into a bounded buffer and count the rest; for the others it only decides and
/// continues. Sanitization, serialization and export run later on background tasks. The framework route comes from the endpoint's
/// <c>RoutePattern</c> (sanitizer.md 3.4, ASP.NET Core row). The ambient <see cref="Activity"/> (OpenTelemetry or ASP.NET Core's own)
/// is only READ.
/// </summary>
public sealed class TrafficTwinMiddleware
{
    private readonly RequestDelegate next;
    private readonly TrafficTwinAgent? agent;

    public TrafficTwinMiddleware(RequestDelegate next, TrafficTwinAgent? agent = null)
    {
        this.next = next;
        this.agent = agent;
    }

    private sealed class InState
    {
        public Sanitizer San = null!;
        public Decision Decision;
        public ExchangeCtx Ctx = null!;
        public string? ParentSpanId;
        public long T0;
        public long TsMs;
        public BodyTap ReqTap = null!;
        public BodyTap ResTap = null!;
        public long OverheadTicks;
        /// <summary>PathBase when the exchange began: UsePathBase restores it before the response completes.</summary>
        public string PathBase = "";
    }

    public async Task InvokeAsync(HttpContext http)
    {
        ICaptureHost? host = agent ?? TrafficTwinAgent.Current;
        Sanitizer? san = host?.Active();
        if (host == null || san == null)
        {
            await next(http).ConfigureAwait(false);
            return;
        }
        InState? st = null;
        Stream? originalRequestBody = null;
        try
        {
            st = Begin(host, san, http);
            if (st != null)
            {
                originalRequestBody = http.Request.Body;
                http.Request.Body = new TeeReadStream(originalRequestBody, st.ReqTap);
                // Registered BEFORE the body is replaced: callbacks run last-registered-first, so ours runs after the framework
                // has flushed what the app wrote through Response.BodyWriter into the tee.
                InState captured = st;
                http.Response.OnCompleted(() =>
                {
                    Finish(host, captured, http);
                    return Task.CompletedTask;
                });
                http.Response.Body = new TeeWriteStream(http.Response.Body, st.ResTap);
            }
        }
        catch (Exception)
        {
            host.NoteError("capture_inbound_start");
        }
        try
        {
            await next(http).ConfigureAwait(false);
        }
        finally
        {
            if (originalRequestBody != null)
            {
                try { http.Request.Body = originalRequestBody; }
                catch (Exception) { /* ignore */ }
            }
        }
    }

    private InState? Begin(ICaptureHost host, Sanitizer san, HttpContext http)
    {
        long t = Stopwatch.GetTimestamp();
        host.NoteSeen();
        HttpRequest req = http.Request;
        string? tpHeader = req.Headers.TryGetValue("traceparent", out var tpv) && tpv.Count > 0 ? tpv[0] : null;
        var tp = tpHeader == null ? null : ExchangeContext.ParseTraceparent(tpHeader);
        var act = ExchangeContext.ActiveActivity();
        // The trace id used for sampling is only one that came from upstream (traceparent, or an Activity that has a parent).
        string? samplingTrace = tp?.TraceId;
        if (samplingTrace == null && act != null && Activity.Current?.ParentId != null) samplingTrace = act.Value.TraceId;
        var names = host.DecisionHeaders;
        var hdrs = new List<(string, byte[])>();
        foreach (var h in req.Headers)
        {
            if (names.Contains(h.Key))
            {
                foreach (string? v in h.Value) hdrs.Add((h.Key, Utf8Util.Latin1(v ?? "")));
            }
        }
        Decision decision = san.Decide(true, host.ServiceName, hdrs, samplingTrace, null);
        var ctx = new ExchangeCtx
        {
            Sampled = decision.Sampled,
            TraceId = tp?.TraceId ?? act?.TraceId ?? ExchangeContext.NewTraceId(),
            TraceKnown = tp != null || act != null,
            SpanId = (act != null && !string.IsNullOrEmpty(act.Value.SpanId)) ? act.Value.SpanId : ExchangeContext.NewSpanId(),
        };
        // Bind the rest of this request's async work (handlers, outbound calls) to ctx.
        ExchangeContext.Current = ctx;
        if (!decision.Sampled)
        {
            host.NoteOverhead(TicksToNs(Stopwatch.GetTimestamp() - t));
            return null;
        }
        host.NoteSampled();
        long limit = san.Policy.CaptureLimit; // 9.0, 22.5: max(max_body_bytes, bodies.max_large_body_bytes) + 1
        return new InState
        {
            San = san,
            Decision = decision,
            Ctx = ctx,
            ParentSpanId = tp?.SpanId ?? act?.ParentSpanId,
            T0 = Stopwatch.GetTimestamp(),
            TsMs = CaptureUtil.NowMs(),
            ReqTap = new BodyTap(limit),
            ResTap = new BodyTap(limit),
            OverheadTicks = Stopwatch.GetTimestamp() - t,
            PathBase = http.Request.PathBase.HasValue ? http.Request.PathBase.Value! : "",
        };
    }

    private static long TicksToNs(long ticks) => (long)(ticks * (1_000_000_000.0 / Stopwatch.Frequency));

    private static (byte[] Path, byte[]? Query) SplitTarget(HttpRequest req)
    {
        string? target = req.HttpContext.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (string.IsNullOrEmpty(target))
        {
            // No raw target (in-memory hosts): rebuild from the decoded parts; encoded slashes are lost there.
            string p = req.PathBase.Add(req.Path).ToUriComponent();
            string q = req.QueryString.HasValue ? req.QueryString.Value![1..] : "";
            return (Utf8Util.Latin1(p.Length == 0 ? "/" : p), req.QueryString.HasValue ? Utf8Util.Latin1(q) : null);
        }
        int sc = target.IndexOf("://", StringComparison.Ordinal);
        if (sc > 0 && sc < 16)
        {
            int slash = target.IndexOfAny(new[] { '/', '?', '#' }, sc + 3);
            target = slash < 0 ? "/" : target.Substring(slash);
        }
        if (target.Length == 0 || target[0] != '/' && target[0] != '?') target = "/" + (target == "*" ? "" : target);
        int hash = target.IndexOf('#');
        if (hash >= 0) target = target.Substring(0, hash);
        int qi = target.IndexOf('?');
        if (qi < 0) return (Utf8Util.Latin1(target), null);
        string path = target.Substring(0, qi);
        return (Utf8Util.Latin1(path.Length == 0 ? "/" : path), Utf8Util.Latin1(target.Substring(qi + 1)));
    }

    /// <summary>The complete route template (mount prefixes included) of the matched endpoint (sanitizer.md 3.3, 3.4), or null.</summary>
    private static string? FrameworkRoute(HttpContext http, string pathBase)
    {
        if (http.GetEndpoint() is not RouteEndpoint re) return null;
        string? raw = re.RoutePattern.RawText;
        if (string.IsNullOrEmpty(raw)) return null;
        string prefix = pathBase.TrimEnd('/');
        return prefix + "/" + raw.TrimStart('/');
    }

    private static void AddHeaders(List<(string, byte[])> dst, IHeaderDictionary headers)
    {
        foreach (var h in headers)
        {
            foreach (string? v in h.Value) dst.Add((h.Key, Utf8Util.Latin1(v ?? "")));
        }
    }

    private static void Finish(ICaptureHost host, InState st, HttpContext http)
    {
        long t = Stopwatch.GetTimestamp();
        try
        {
            long latencyMs = Math.Max(0, (long)((t - st.T0) * 1000.0 / Stopwatch.Frequency));
            HttpRequest req = http.Request;
            HttpResponse res = http.Response;
            int status = res.StatusCode;
            string method = req.Method;
            // 9.0: a body the app did not read to the end is "not consumed"; an empty body is complete.
            bool canHaveBody = http.Features.Get<IHttpRequestBodyDetectionFeature>()?.CanHaveBody ?? (req.ContentLength > 0 || req.Headers.ContainsKey("Transfer-Encoding"));
            bool reqConsumed = st.ReqTap.Ended || !canHaveBody || (req.ContentLength.HasValue && st.ReqTap.Total >= req.ContentLength.Value);
            bool noBody = HttpMethods.IsHead(method) || status == 204 || status == 304 || (status >= 100 && status < 200);
            var (path, query) = SplitTarget(req);
            string? route = FrameworkRoute(http, st.PathBase);
            var reqHeaders = new List<(string, byte[])>();
            AddHeaders(reqHeaders, req.Headers);
            var respHeaders = new List<(string, byte[])>();
            AddHeaders(respHeaders, res.Headers);
            byte[] reqBody = reqConsumed ? st.ReqTap.Bytes() : Array.Empty<byte>();
            byte[] resBody = noBody ? Array.Empty<byte>() : st.ResTap.Bytes();
            long reqTotal = st.ReqTap.Total;
            long resTotal = noBody ? 0 : st.ResTap.Total;
            string serviceName = host.ServiceName;
            string? traceId = st.Ctx.TraceKnown ? st.Ctx.TraceId : null;
            host.Submit(new RawExchange
            {
                Sanitizer = st.San,
                Decision = st.Decision,
                Inbound = true,
                TsMs = st.TsMs,
                LatencyMs = latencyMs,
                TraceId = st.Ctx.TraceId,
                SpanId = st.Ctx.SpanId,
                ParentSpanId = st.ParentSpanId,
                Status = status,
                HeldBytes = reqBody.Length + resBody.Length,
                Build = () => new Exchange
                {
                    Inbound = true,
                    ServiceName = serviceName,
                    Method = method,
                    RawPath = path,
                    RawQuery = query,
                    Framework = route != null ? "aspnetcore" : null,
                    FrameworkRoute = route,
                    TraceId = traceId,
                    ReqHeaders = reqHeaders,
                    ReqBody = reqBody,
                    ReqBodyTotal = reqTotal,
                    ReqBodyConsumed = reqConsumed,
                    Status = status,
                    RespHeaders = respHeaders,
                    RespBody = resBody,
                    RespBodyTotal = resTotal,
                },
            });
        }
        catch (Exception)
        {
            host.NoteError("capture_inbound_finish");
        }
        host.NoteOverhead(TicksToNs(st.OverheadTicks + (Stopwatch.GetTimestamp() - t)));
    }
}
