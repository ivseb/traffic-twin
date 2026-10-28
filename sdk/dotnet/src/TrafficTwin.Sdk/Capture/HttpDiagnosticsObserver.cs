using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;
using TrafficTwin.Sdk.Sanitizing;

namespace TrafficTwin.Sdk.Capture;

/// <summary>
/// Outbound metadata for <see cref="HttpClient"/> instances that do NOT go through <see cref="TrafficTwinHandler"/>
/// (for example <c>new HttpClient()</c>), from the legacy events of the <c>HttpHandlerDiagnosticListener</c>.
/// Those events carry the request and response messages but not the body bytes, so the bodies are reported as
/// not captured (<c>trunc:size</c>); requests that went through the handler are skipped.
///
/// The subscription enables ONLY <c>System.Net.Http.Request</c>, <c>.Response</c> and <c>.Exception</c>. It never enables
/// <c>System.Net.Http.HttpRequestOut</c> (the activity event), so subscribing does not make the runtime create an
/// <see cref="Activity"/> or inject <c>traceparent</c> into the app's requests.
/// </summary>
internal sealed class HttpDiagnosticsObserver : IObserver<DiagnosticListener>, IDisposable
{
    private const string ListenerName = "HttpHandlerDiagnosticListener";
    private const string RequestEvent = "System.Net.Http.Request";
    private const string ResponseEvent = "System.Net.Http.Response";
    private const string ExceptionEvent = "System.Net.Http.Exception";

    private readonly ICaptureHost host;
    private readonly List<IDisposable> subscriptions = new();
    private IDisposable? all;
    private readonly ConditionalWeakTable<HttpRequestMessage, Pending> table = new();
    private volatile bool disposed;

    private sealed class Pending
    {
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
        public List<(string, byte[])> ReqHeaders = new();
        public bool HasRequestBody;
        public int Done;
    }

    private HttpDiagnosticsObserver(ICaptureHost host) { this.host = host; }

    public static HttpDiagnosticsObserver Install(ICaptureHost host)
    {
        var o = new HttpDiagnosticsObserver(host);
        o.all = DiagnosticListener.AllListeners.Subscribe(o);
        return o;
    }

    public void OnCompleted() { }

    public void OnError(Exception error) { }

    public void OnNext(DiagnosticListener value)
    {
        if (disposed || value.Name != ListenerName) return;
        lock (subscriptions)
        {
            subscriptions.Add(value.Subscribe(new EventObserver(this), static (name, _, _) => name == RequestEvent || name == ResponseEvent || name == ExceptionEvent));
        }
    }

    public void Dispose()
    {
        disposed = true;
        all?.Dispose();
        lock (subscriptions)
        {
            foreach (var s in subscriptions) s.Dispose();
            subscriptions.Clear();
        }
    }

    private sealed class EventObserver : IObserver<KeyValuePair<string, object?>>
    {
        private readonly HttpDiagnosticsObserver owner;
        public EventObserver(HttpDiagnosticsObserver o) { owner = o; }
        public void OnCompleted() { }
        public void OnError(Exception error) { }

        public void OnNext(KeyValuePair<string, object?> e)
        {
            if (owner.disposed || e.Value == null) return;
            try
            {
                switch (e.Key)
                {
                    case RequestEvent: owner.OnRequest(Get<HttpRequestMessage>(e.Value, "Request")); break;
                    case ResponseEvent: owner.OnResponse(Get<HttpResponseMessage>(e.Value, "Response"), null); break;
                    case ExceptionEvent: owner.OnResponse(null, Get<HttpRequestMessage>(e.Value, "Request"), Get<Exception>(e.Value, "Exception")); break;
                }
            }
            catch (Exception)
            {
                owner.host.NoteError("capture_outbound_diag");
            }
        }
    }

    private static readonly ConditionalWeakTable<Type, Dictionary<string, PropertyInfo?>> PropCache = new();

    private static T? Get<T>(object payload, string name) where T : class
    {
        Dictionary<string, PropertyInfo?> props = PropCache.GetValue(payload.GetType(), _ => new Dictionary<string, PropertyInfo?>(StringComparer.Ordinal));
        PropertyInfo? p;
        lock (props)
        {
            if (!props.TryGetValue(name, out p))
            {
                p = payload.GetType().GetProperty(name, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
                props[name] = p;
            }
        }
        return p?.GetValue(payload) as T;
    }

    private void OnRequest(HttpRequestMessage? request)
    {
        if (request == null) return;
        long t = Stopwatch.GetTimestamp();
        Sanitizer? san = host.Active();
        if (san == null) return;
        if (request.Options.TryGetValue(CaptureUtil.InternalKey, out bool isInternal) && isInternal) return;
        if (request.Options.TryGetValue(CaptureUtil.HandledKey, out bool handled) && handled) return;
        Uri? uri = request.RequestUri;
        if (uri == null || !uri.IsAbsoluteUri) return;
        host.NoteSeen();
        ExchangeCtx? ctx = ExchangeContext.Current;
        var (traceId, parentSpanId, samplingTraceId) = TrafficTwinHandler.OutboundTraceFor(ctx);
        Decision decision = san.Decide(false, null, null, samplingTraceId, ctx?.Sampled);
        if (!decision.Sampled) return;
        host.NoteSampled();
        var (path, query) = CaptureUtil.SplitUri(uri);
        var p = new Pending
        {
            San = san,
            Decision = decision,
            UrlBase = CaptureUtil.UrlBase(uri),
            Method = request.Method.Method,
            RawPath = path,
            RawQuery = query,
            TraceId = traceId,
            SpanId = ExchangeContext.NewSpanId(),
            ParentSpanId = parentSpanId,
            T0 = Stopwatch.GetTimestamp(),
            TsMs = CaptureUtil.NowMs(),
            HasRequestBody = request.Content != null,
        };
        CaptureUtil.AddHeaders(p.ReqHeaders, request.Headers);
        if (request.Content != null) CaptureUtil.AddHeaders(p.ReqHeaders, request.Content.Headers);
        table.AddOrUpdate(request, p);
        host.NoteOverhead((long)((Stopwatch.GetTimestamp() - t) * (1_000_000_000.0 / Stopwatch.Frequency)));
    }

    private void OnResponse(HttpResponseMessage? response, HttpRequestMessage? request, Exception? error = null)
    {
        request ??= response?.RequestMessage;
        if (request == null || !table.TryGetValue(request, out Pending? p)) return;
        table.Remove(request);
        if (Interlocked.Exchange(ref p.Done, 1) != 0) return;
        long latencyMs = Math.Max(0, (long)((Stopwatch.GetTimestamp() - p.T0) * 1000.0 / Stopwatch.Frequency));
        int? status = response != null ? (int)response.StatusCode : null;
        string? err = response != null ? null : CaptureUtil.NetErrorOf(error);
        var respHeaders = new List<(string, byte[])>();
        if (response != null)
        {
            CaptureUtil.AddHeaders(respHeaders, response.Headers);
            if (response.Content != null) CaptureUtil.AddHeaders(respHeaders, response.Content.Headers);
        }
        host.Submit(new RawExchange
        {
            Sanitizer = p.San,
            Decision = p.Decision,
            Inbound = false,
            TsMs = p.TsMs,
            LatencyMs = latencyMs,
            TraceId = p.TraceId,
            SpanId = p.SpanId,
            ParentSpanId = p.ParentSpanId,
            Status = status,
            NetError = err,
            HeldBytes = 0,
            Build = () =>
            {
                var ex = new Exchange
                {
                    Inbound = false,
                    UrlBase = p.UrlBase,
                    Method = p.Method,
                    RawPath = p.RawPath,
                    RawQuery = p.RawQuery,
                    Inherited = p.Decision.By == "inherited" ? p.Decision.Sampled : null,
                    ReqHeaders = p.ReqHeaders,
                    ReqBody = Array.Empty<byte>(),
                    // The message events do not carry the body bytes: not captured.
                    ReqBodyTotal = p.HasRequestBody ? Exchange.UnknownTotal : 0,
                };
                if (err != null) ex.NetError = err;
                else
                {
                    ex.Status = status;
                    ex.RespHeaders = respHeaders;
                    ex.RespBody = Array.Empty<byte>();
                    ex.RespBodyTotal = Exchange.UnknownTotal;
                    ex.RespBodyConsumed = false;
                }
                return ex;
            },
        });
    }
}
