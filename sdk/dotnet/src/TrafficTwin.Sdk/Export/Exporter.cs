using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TrafficTwin.Sdk.Capture;

namespace TrafficTwin.Sdk.Export;

/// <summary>Counters shared with the heartbeat; all updated with <see cref="Interlocked"/>.</summary>
internal sealed class Counters
{
    public long ExchangesSeen, ExchangesSampled, EventsSent, EventsDroppedQueue, EventsRejected, SendErrors, SanitizerErrors;

    public static long Get(ref long f) => Interlocked.Read(ref f);
}

/// <summary>
/// OTLP/HTTP JSON exporter (event.md 4): bounded queue, batches of at most 512 events or 4 MiB, retry with exponential
/// backoff and jitter on 429/502/503/504 and network errors (at most 5 times, Retry-After honoured), drop-oldest under
/// pressure. The app never waits: events are queued from a background worker and sent by a background task.
/// </summary>
internal sealed class Exporter : IAsyncDisposable
{
    private static readonly HashSet<int> Retryable = new() { 429, 502, 503, 504 };
    private static readonly HashSet<int> DropStatuses = new() { 400, 401, 403, 413 };

    private readonly Counters counters;
    private readonly Action<string> onError;
    private readonly string serviceName;
    private readonly string sourceId;
    private readonly int maxEvents;
    private readonly long maxBytes;
    private readonly int batchEvents;
    private readonly long batchBytes;
    private readonly TimeSpan flushInterval;
    private readonly int maxRetries;
    private readonly TimeSpan baseBackoff;
    private readonly TimeSpan maxBackoff;

    private readonly Channel<QueuedEvent> queue;
    private long queuedBytes;
    private readonly SemaphoreSlim sendLock = new(1, 1);
    private readonly SemaphoreSlim kick = new(0, int.MaxValue);
    private readonly CancellationTokenSource cts = new();
    private readonly Task loop;
    private volatile HttpClient http;
    private volatile string url;
    private volatile bool stopped;

    public Exporter(HttpClient http, string url, string serviceName, string sourceId, Counters counters, Action<string> onError, TimeSpan? flushInterval = null,
        int maxEvents = 10_000, long maxBytes = 16 << 20, int batchEvents = 512, long batchBytes = 4 << 20, int maxRetries = 5,
        TimeSpan? baseBackoff = null, TimeSpan? maxBackoff = null)
    {
        this.http = http;
        this.url = url;
        this.serviceName = serviceName;
        this.sourceId = sourceId;
        this.counters = counters;
        this.onError = onError;
        this.flushInterval = flushInterval ?? TimeSpan.FromSeconds(1);
        this.maxEvents = maxEvents;
        this.maxBytes = maxBytes;
        this.batchEvents = batchEvents;
        this.batchBytes = batchBytes;
        this.maxRetries = maxRetries;
        this.baseBackoff = baseBackoff ?? TimeSpan.FromSeconds(1);
        this.maxBackoff = maxBackoff ?? TimeSpan.FromSeconds(30);
        queue = Channel.CreateBounded<QueuedEvent>(new BoundedChannelOptions(maxEvents)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = false,
            SingleWriter = false,
        }, dropped =>
        {
            Interlocked.Add(ref queuedBytes, -dropped.Json.Length);
            Interlocked.Increment(ref counters.EventsDroppedQueue);
        });
        loop = Task.Run(RunAsync);
    }

    public (int Events, long Bytes) Size => (queue.Reader.Count, Interlocked.Read(ref queuedBytes));

    public void SetTarget(HttpClient newClient, string newUrl)
    {
        http = newClient;
        url = newUrl;
    }

    private long gen;

    /// <summary>Kill-switch generation: <see cref="Clear"/> bumps it; a batch taken under an older one is dropped, never (re)sent.</summary>
    public long Generation => Interlocked.Read(ref gen);

    /// <param name="atGen">The generation read before the event was built; an older one means the kill switch arrived meanwhile (-1: unconditional).</param>
    public void Enqueue(QueuedEvent e, long atGen = -1)
    {
        if (stopped) return;
        if (atGen >= 0 && atGen != Interlocked.Read(ref gen))
        {
            Interlocked.Increment(ref counters.EventsDroppedQueue);
            return;
        }
        Interlocked.Add(ref queuedBytes, e.Json.Length);
        queue.Writer.TryWrite(e);
        while (Interlocked.Read(ref queuedBytes) > maxBytes && queue.Reader.TryRead(out QueuedEvent? old))
        {
            Interlocked.Add(ref queuedBytes, -old.Json.Length);
            Interlocked.Increment(ref counters.EventsDroppedQueue);
        }
        if (queue.Reader.Count >= batchEvents) kick.Release();
    }

    /// <summary>Drops everything queued (kill switch).</summary>
    public void Clear()
    {
        Interlocked.Increment(ref gen);
        while (queue.Reader.TryRead(out QueuedEvent? old))
        {
            Interlocked.Add(ref queuedBytes, -old.Json.Length);
            Interlocked.Increment(ref counters.EventsDroppedQueue);
        }
    }

    /// <summary>Sends what is queued; returns when the queue is empty or a send failed.</summary>
    public async Task FlushAsync()
    {
        for (int i = 0; i < 1000 && queue.Reader.Count > 0 && !stopped; i++)
        {
            await sendLock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (queue.Reader.Count == 0) return;
                bool ok = await SendOneAsync().ConfigureAwait(false);
                if (!ok) return;
            }
            finally
            {
                sendLock.Release();
            }
        }
    }

    private async Task RunAsync()
    {
        try
        {
            while (!stopped)
            {
                try { await kick.WaitAsync(flushInterval, cts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                if (queue.Reader.Count == 0) continue;
                await sendLock.WaitAsync(cts.Token).ConfigureAwait(false);
                try
                {
                    if (queue.Reader.Count > 0) await SendOneAsync().ConfigureAwait(false);
                }
                finally
                {
                    sendLock.Release();
                }
            }
        }
        catch (OperationCanceledException)
        {
            // stopping
        }
        catch (Exception)
        {
            onError("exporter_loop");
        }
    }

    private List<QueuedEvent> TakeBatch()
    {
        var batch = new List<QueuedEvent>();
        long size = 0;
        while (batch.Count < batchEvents && queue.Reader.TryPeek(out QueuedEvent? e))
        {
            if (batch.Count > 0 && size + e.Json.Length > batchBytes) break;
            if (!queue.Reader.TryRead(out e)) break;
            batch.Add(e);
            size += e.Json.Length;
            Interlocked.Add(ref queuedBytes, -e.Json.Length);
        }
        return batch;
    }

    private async Task<bool> SendOneAsync()
    {
        long batchGen = Interlocked.Read(ref gen);
        List<QueuedEvent> batch = TakeBatch();
        if (batch.Count == 0) return true;
        for (int attempt = 0; ; attempt++)
        {
            if (batchGen != Interlocked.Read(ref gen))
            {
                // the kill switch arrived: a batch built under an older generation is never (re)sent
                Interlocked.Add(ref counters.EventsDroppedQueue, batch.Count);
                return false;
            }
            HttpResponseMessage? res = null;
            string? body = null;
            bool netErr = false;
            try
            {
                byte[] payload = EventBuilder.OtlpBody(batch, serviceName, sourceId, CaptureUtil.NowMs());
                using var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = new ByteArrayContent(payload) };
                req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                req.Options.Set(CaptureUtil.InternalKey, true);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);
                timeout.CancelAfter(TimeSpan.FromSeconds(15));
                res = await http.SendAsync(req, HttpCompletionOption.ResponseContentRead, timeout.Token).ConfigureAwait(false);
                body = await res.Content.ReadAsStringAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (Exception)
            {
                netErr = true;
            }
            int status = res != null ? (int)res.StatusCode : 0;
            if (res != null && !netErr && status >= 200 && status < 300)
            {
                long rejected = 0;
                try
                {
                    if (!string.IsNullOrWhiteSpace(body))
                    {
                        using var doc = JsonDocument.Parse(body);
                        if (doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("partialSuccess", out var ps) &&
                            ps.ValueKind == JsonValueKind.Object && ps.TryGetProperty("rejectedLogRecords", out var rr))
                        {
                            rejected = rr.ValueKind == JsonValueKind.Number ? rr.GetInt64() :
                                       rr.ValueKind == JsonValueKind.String && long.TryParse(rr.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out long v) ? v : 0;
                        }
                    }
                }
                catch (Exception) { rejected = 0; }
                rejected = Math.Min(Math.Max(0, rejected), batch.Count);
                Interlocked.Add(ref counters.EventsSent, batch.Count - rejected);
                Interlocked.Add(ref counters.EventsRejected, rejected);
                if (rejected > 0) onError("intake_partial_reject");
                res.Dispose();
                return true;
            }
            bool retryable = netErr || Retryable.Contains(status);
            if (!retryable || attempt >= maxRetries || stopped)
            {
                if (res != null && DropStatuses.Contains(status)) Interlocked.Add(ref counters.EventsRejected, batch.Count);
                else Interlocked.Add(ref counters.EventsDroppedQueue, batch.Count);
                Interlocked.Increment(ref counters.SendErrors);
                onError(res != null ? "intake_http_" + status.ToString(CultureInfo.InvariantCulture) : "intake_network");
                res?.Dispose();
                return false;
            }
            Interlocked.Increment(ref counters.SendErrors);
            double delay = Math.Min(maxBackoff.TotalMilliseconds, baseBackoff.TotalMilliseconds * Math.Pow(2, attempt));
            delay = delay / 2 + Random.Shared.NextDouble() * (delay / 2);
            RetryConditionHeaderValue? ra = res?.Headers.RetryAfter;
            if (ra != null)
            {
                double ms = ra.Delta.HasValue ? ra.Delta.Value.TotalMilliseconds : ra.Date.HasValue ? (ra.Date.Value - DateTimeOffset.UtcNow).TotalMilliseconds : 0;
                if (ms > 0) delay = Math.Min(Math.Max(delay, ms), 300_000);
            }
            res?.Dispose();
            try { await Task.Delay(TimeSpan.FromMilliseconds(delay), cts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { return false; }
            if (stopped) return false;
        }
    }

    public async ValueTask DisposeAsync()
    {
        stopped = true;
        cts.Cancel();
        try { await loop.ConfigureAwait(false); }
        catch (Exception) { /* stopping */ }
        cts.Dispose();
    }
}
