using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using TrafficTwin.Sdk.Capture;
using TrafficTwin.Sdk.Sanitizing;

namespace TrafficTwin.Sdk;

/// <summary>
/// Outbound capture for <see cref="HttpClient"/>: a <see cref="DelegatingHandler"/> to put in the handler chain
/// (<c>IHttpClientFactory</c>: <c>AddTrafficTwin()</c> of TrafficTwin.Sdk.AspNetCore does it for every client).
/// It tees the request and response bodies of SAMPLED exchanges and never changes what is sent or received. It does not
/// inject <c>traceparent</c>; the only header it may add is the <c>tt.s</c> baggage member toward hosts listed in
/// <c>sampling.propagate_to</c> (sanitizer.md 12).
/// </summary>
public sealed class TrafficTwinHandler : DelegatingHandler
{
    /// <summary>How long an unread response body is waited for before the exchange is closed as not consumed.</summary>
    internal static readonly TimeSpan UnreadBodyTimeout = TimeSpan.FromSeconds(60);

    private readonly TrafficTwinAgent? agent;

    /// <summary>Uses the process-wide agent (<see cref="TrafficTwinAgent.Current"/>), resolved at each call.</summary>
    public TrafficTwinHandler() { }

    public TrafficTwinHandler(HttpMessageHandler innerHandler) : base(innerHandler) { }

    public TrafficTwinHandler(TrafficTwinAgent agent, HttpMessageHandler? innerHandler = null)
    {
        this.agent = agent;
        if (innerHandler != null) InnerHandler = innerHandler;
    }

    private sealed class State
    {
        public ICaptureHost Host = null!;
        public Sanitizer San = null!;
        public Decision Decision;
        public string UrlBase = "";
        public string Method = "";
        public byte[] RawPath = Array.Empty<byte>();
        public byte[]? RawQuery;
        public string TraceId = "";
        public string SpanId = "";
        public string? ParentSpanId;
        public long T0;
        public long TsMs;
        public BodyTap ReqTap = null!;
        public BodyTap ResTap = null!;
        public List<(string, byte[])> ReqHeaders = new();
        public long OverheadTicks;
        public int Done;
        public HttpContent? OriginalContent;
        public bool HasRequestBody;
        public Timer? Timer;
    }

    private ICaptureHost? Host => agent ?? TrafficTwinAgent.Current;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        State? st = Begin(request);
        if (st == null) return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        HttpResponseMessage response;
        try
        {
            response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            Fail(st, request, e);
            throw;
        }
        AfterHeaders(st, request, response);
        return response;
    }

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        State? st = Begin(request);
        if (st == null) return base.Send(request, cancellationToken);
        HttpResponseMessage response;
        try
        {
            response = base.Send(request, cancellationToken);
        }
        catch (Exception e)
        {
            Fail(st, request, e);
            throw;
        }
        AfterHeaders(st, request, response);
        return response;
    }

    private State? Begin(HttpRequestMessage request)
    {
        long t = Stopwatch.GetTimestamp();
        try
        {
            ICaptureHost? host = Host;
            if (host == null) return null;
            Sanitizer? san = host.Active();
            if (san == null) return null;
            if (request.Options.TryGetValue(CaptureUtil.InternalKey, out bool isInternal) && isInternal) return null;
            Uri? uri = request.RequestUri;
            if (uri == null || !uri.IsAbsoluteUri) return null;
            request.Options.Set(CaptureUtil.HandledKey, true);
            host.NoteSeen();
            string urlBase = CaptureUtil.UrlBase(uri);
            ExchangeCtx? ctx = ExchangeContext.Current;
            var (traceId, parentSpanId, samplingTraceId) = OutboundTrace(ctx);
            Decision decision = san.Decide(false, null, null, samplingTraceId, ctx?.Sampled);
            if (host.MayPropagate(urlBase))
            {
                try
                {
                    string? prev = request.Headers.TryGetValues("baggage", out var vals) ? string.Join(",", vals) : null;
                    request.Headers.Remove("baggage");
                    request.Headers.TryAddWithoutValidation("baggage", CaptureUtil.WithTtS(prev, decision.Sampled));
                }
                catch (Exception)
                {
                    // leave the request as it was
                }
            }
            if (!decision.Sampled)
            {
                host.NoteOverhead(TicksToNs(Stopwatch.GetTimestamp() - t));
                return null;
            }
            host.NoteSampled();
            long limit = san.Policy.CaptureLimit; // 9.0, 22.5: max(max_body_bytes, bodies.max_large_body_bytes) + 1
            var (path, query) = CaptureUtil.SplitUri(uri);
            var st = new State
            {
                Host = host,
                San = san,
                Decision = decision,
                UrlBase = urlBase,
                Method = request.Method.Method,
                RawPath = path,
                RawQuery = query,
                TraceId = traceId,
                SpanId = ExchangeContext.NewSpanId(),
                ParentSpanId = parentSpanId,
                T0 = Stopwatch.GetTimestamp(),
                TsMs = CaptureUtil.NowMs(),
                ReqTap = new BodyTap(limit),
                ResTap = new BodyTap(limit),
            };
            CaptureUtil.AddHeaders(st.ReqHeaders, request.Headers);
            if (request.Content != null)
            {
                CaptureUtil.AddHeaders(st.ReqHeaders, request.Content.Headers);
                st.OriginalContent = request.Content;
                st.HasRequestBody = true;
                request.Content = new TeeRequestContent(request.Content, st.ReqTap);
            }
            st.OverheadTicks = Stopwatch.GetTimestamp() - t;
            return st;
        }
        catch (Exception)
        {
            Host?.NoteError("capture_outbound_start");
            return null;
        }
    }

    private static (string TraceId, string? ParentSpanId, string? SamplingTraceId) OutboundTrace(ExchangeCtx? ctx)
    {
        var act = ExchangeContext.ActiveActivity();
        if (ctx != null)
        {
            // Adopt the ambient trace id when the inbound request carried none, so inbound and outbound events share the app's own trace.
            if (!ctx.TraceKnown && act != null)
            {
                ctx.TraceId = act.Value.TraceId;
                ctx.TraceKnown = true;
            }
            return (ctx.TraceId, ctx.SpanId, null);
        }
        if (act != null) return (act.Value.TraceId, string.IsNullOrEmpty(act.Value.SpanId) ? null : act.Value.SpanId, act.Value.TraceId);
        return (ExchangeContext.NewTraceId(), null, null);
    }

    internal static (string TraceId, string? ParentSpanId, string? SamplingTraceId) OutboundTraceFor(ExchangeCtx? ctx) => OutboundTrace(ctx);

    private static long TicksToNs(long ticks) => (long)(ticks * (1_000_000_000.0 / Stopwatch.Frequency));

    private static void AfterHeaders(State st, HttpRequestMessage request, HttpResponseMessage response)
    {
        try
        {
            // The original request content is the owner of its own lifetime; give it back.
            if (st.OriginalContent != null) request.Content = st.OriginalContent;
            HttpContent content = response.Content;
            long? len = content.Headers.ContentLength;
            bool noBody = request.Method == HttpMethod.Head || len == 0 ||
                          response.StatusCode == System.Net.HttpStatusCode.NoContent || response.StatusCode == System.Net.HttpStatusCode.NotModified ||
                          ((int)response.StatusCode >= 100 && (int)response.StatusCode < 200);
            if (noBody)
            {
                Complete(st, response, null, ended: true, noBody: true);
                return;
            }
            // Wrap the content so that the bytes the app reads are teed. A response nobody reads is closed by a timeout.
            response.Content = new TeeResponseContent(content, st.ResTap, ended => Complete(st, response, null, ended, noBody: false));
            st.Timer = new Timer(_ => Complete(st, response, null, ended: false, noBody: false), null, UnreadBodyTimeout, Timeout.InfiniteTimeSpan);
        }
        catch (Exception)
        {
            st.Host.NoteError("capture_outbound_response");
        }
    }

    private static void Fail(State st, HttpRequestMessage request, Exception e)
    {
        try
        {
            if (st.OriginalContent != null) request.Content = st.OriginalContent;
        }
        catch (Exception)
        {
            // ignore
        }
        Complete(st, null, CaptureUtil.NetErrorOf(e), ended: false, noBody: false);
    }

    private static void Complete(State st, HttpResponseMessage? response, string? netError, bool ended, bool noBody)
    {
        if (System.Threading.Interlocked.Exchange(ref st.Done, 1) != 0) return;
        long t = Stopwatch.GetTimestamp();
        try
        {
            st.Timer?.Dispose();
            long latencyMs = Math.Max(0, (long)((t - st.T0) * 1000.0 / Stopwatch.Frequency));
            int? status = response != null ? (int)response.StatusCode : null;
            string? err = response != null ? null : netError ?? "other";
            byte[] reqBody = st.ReqTap.Bytes();
            long reqTotal = st.ReqTap.Total;
            bool reqComplete = !st.HasRequestBody || st.ReqTap.Ended;
            bool resConsumed = noBody || (ended && st.ResTap.Ended);
            byte[] resBody = response != null && resConsumed ? st.ResTap.Bytes() : Array.Empty<byte>();
            long resTotal = noBody ? 0 : st.ResTap.Total;
            var respHeaders = new List<(string, byte[])>();
            if (response != null)
            {
                CaptureUtil.AddHeaders(respHeaders, response.Headers);
                if (response.Content != null) CaptureUtil.AddHeaders(respHeaders, response.Content.Headers);
            }
            var raw = new RawExchange
            {
                Sanitizer = st.San,
                Decision = st.Decision,
                Inbound = false,
                TsMs = st.TsMs,
                LatencyMs = latencyMs,
                TraceId = st.TraceId,
                SpanId = st.SpanId,
                ParentSpanId = st.ParentSpanId,
                Status = status,
                NetError = err,
                HeldBytes = reqBody.Length + resBody.Length,
                Build = () =>
                {
                    var ex = new Exchange
                    {
                        Inbound = false,
                        UrlBase = st.UrlBase,
                        Method = st.Method,
                        RawPath = st.RawPath,
                        RawQuery = st.RawQuery,
                        Inherited = st.Decision.By == "inherited" ? st.Decision.Sampled : null,
                        ReqHeaders = st.ReqHeaders,
                        ReqBody = reqBody,
                        ReqBodyTotal = reqComplete ? reqTotal : Exchange.UnknownTotal,
                    };
                    if (err != null) ex.NetError = err;
                    else
                    {
                        ex.Status = status;
                        ex.RespHeaders = respHeaders;
                        ex.RespBody = resBody;
                        ex.RespBodyTotal = resTotal;
                        ex.RespBodyConsumed = resConsumed;
                    }
                    return ex;
                },
            };
            st.Host.Submit(raw);
        }
        catch (Exception)
        {
            st.Host.NoteError("capture_outbound_complete");
        }
        st.Host.NoteOverhead(TicksToNs(st.OverheadTicks + (Stopwatch.GetTimestamp() - t)));
    }
}
