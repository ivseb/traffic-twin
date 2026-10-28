using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TrafficTwin.Sdk.Capture;
using TrafficTwin.Sdk.Export;
using TrafficTwin.Sdk.Fleet;
using TrafficTwin.Sdk.Sanitizing;

namespace TrafficTwin.Sdk;

/// <summary>Point-in-time view of the agent (tests, diagnostics, health checks). Never contains payload values.</summary>
public sealed record AgentStatus(string State, long ExchangesSeen, long ExchangesSampled, long EventsSent, long EventsDroppedQueue, long EventsRejected, long SendErrors, long SanitizerErrors, int QueueEvents, long QueueBytes);

/// <summary>
/// The agent: Fleet lifecycle (policy.md 4, fleet-api), capture gate, asynchronous sanitization and export. Fail-closed everywhere:
/// any doubt means "do not capture". The application never waits for it: hooks only tee bytes and enqueue; sanitization and export
/// run in background tasks.
/// </summary>
public sealed class TrafficTwinAgent : ICaptureHost, IAsyncDisposable
{
    private const int PendingMax = 2000;
    private const long PendingMaxBytes = 64L << 20;

    private static readonly object CurrentGate = new();
    private static TrafficTwinAgent? current;

    /// <summary>The process-wide agent started by <see cref="Start"/>, or null.</summary>
    public static TrafficTwinAgent? Current => Volatile.Read(ref current);

    /// <summary>
    /// Creates the process-wide agent (idempotent: a second call returns the first) and starts its Fleet cycle in the background.
    /// Never throws and never blocks the caller.
    /// </summary>
    public static TrafficTwinAgent Start(TrafficTwinOptions? options = null)
    {
        lock (CurrentGate)
        {
            if (current != null) return current;
            var agent = new TrafficTwinAgent(options ?? TrafficTwinOptions.FromEnvironment());
            current = agent;
            agent.StartInBackground();
            return agent;
        }
    }

    /// <summary>Stops and forgets the process-wide agent.</summary>
    public static async Task StopCurrentAsync()
    {
        TrafficTwinAgent? a;
        lock (CurrentGate)
        {
            a = current;
            current = null;
        }
        if (a != null) await a.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>Creates an agent that is not the process-wide one (tests). Call <see cref="StartAsync"/> to run it.</summary>
    public static TrafficTwinAgent Create(TrafficTwinOptions options) => new(options);

    /// <summary>Makes this agent the process-wide one (tests).</summary>
    public void SetAsCurrent()
    {
        lock (CurrentGate) current = this;
    }

    private readonly TrafficTwinOptions opts;
    private readonly Counters counters = new();
    private readonly object stateGate = new();
    private readonly CancellationTokenSource cts = new();

    private Sanitizer? san;
    private Policy? policy;
    private string policyKid = "";
    private string? rejected;
    // A heartbeat said a newer policy is current (a normal policy change): capture pauses until it
    // is fetched, and only a failed fetch is an error (policy.md 4).
    private bool switching;
    // One policy poll at a time: the periodic poll and the one a heartbeat starts would otherwise
    // race, and the older answer could arrive last.
    private readonly SemaphoreSlim pollGate = new(1, 1);
    private PolicyChecks.KeyRing? ring;
    private bool heartbeatOk;
    private long lastContact;
    private PersistedState persisted = new();
    private int? overrideBp;
    private IReadOnlySet<string> decisionNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "cookie", "baggage" };
    private readonly long[] overhead = new long[1024];
    private long overheadN;
    private readonly List<(string Code, string At)> lastErrors = new();
    private string state = "starting";

    private Channel<RawExchange> pending = Channel.CreateBounded<RawExchange>(new BoundedChannelOptions(PendingMax) { FullMode = BoundedChannelFullMode.Wait, SingleReader = false });
    private long pendingBytes;
    private long inFlight;
    private long killGen; // kill-switch generation: an exchange sanitized across a bump is never enqueued
    private Task? worker;
    private Task? startTask;
    private Task? loops;
    private bool stopped;

    private StateStore? store;
    private Enrollment? enrollment;
    private string keyPem = "";
    private HttpClient? mtls;
    private X509Certificate2? clientCert;
    private FleetClient? fleet;
    private Exporter? exporter;
    private string? etag;
    private HttpDiagnosticsObserver? observer;

    private TrafficTwinAgent(TrafficTwinOptions options)
    {
        opts = options;
        if (options.Debug) Log.Enabled = true;
    }

    // --- ICaptureHost (hot path) -------------------------------------------------------

    Sanitizer? ICaptureHost.Active() => Volatile.Read(ref san);

    string ICaptureHost.ServiceName => enrollment?.ServiceName ?? "";

    IReadOnlySet<string> ICaptureHost.DecisionHeaders => decisionNames;

    bool ICaptureHost.MayPropagate(string urlBase)
    {
        Policy? p = policy;
        if (p == null || p.PropagateTo.Count == 0) return false;
        UrlBase u = Sanitizer.NormalizeUrlBase(urlBase);
        if (u.Invalid || u.Ip6 != null) return false;
        int c = u.HostPort.LastIndexOf(':');
        string host = c >= 0 ? u.HostPort.Substring(0, c) : u.HostPort;
        // D-M8: never toward a host that matches a policy base (external service).
        if (p.BaseHosts.Contains(u.HostPort) || p.BaseHosts.Contains(host)) return false;
        return p.PropagateTo.Contains(u.HostPort) || p.PropagateTo.Contains(host);
    }

    void ICaptureHost.NoteSeen() => Interlocked.Increment(ref counters.ExchangesSeen);

    void ICaptureHost.NoteSampled() => Interlocked.Increment(ref counters.ExchangesSampled);

    void ICaptureHost.NoteOverhead(long ns) => overhead[(int)((ulong)Interlocked.Increment(ref overheadN) % (ulong)overhead.Length)] = ns;

    void ICaptureHost.NoteError(string code) => NoteError(code);

    void ICaptureHost.Submit(RawExchange raw)
    {
        if (Volatile.Read(ref san) == null || Interlocked.Read(ref pendingBytes) + raw.HeldBytes > PendingMaxBytes)
        {
            Interlocked.Increment(ref counters.EventsDroppedQueue);
            return;
        }
        Interlocked.Add(ref pendingBytes, raw.HeldBytes);
        Interlocked.Increment(ref inFlight);
        if (!pending.Writer.TryWrite(raw))
        {
            Interlocked.Add(ref pendingBytes, -raw.HeldBytes);
            Interlocked.Decrement(ref inFlight);
            Interlocked.Increment(ref counters.EventsDroppedQueue);
        }
    }

    internal void NoteError(string code)
    {
        lock (lastErrors)
        {
            lastErrors.Add((code.Length > 64 ? code.Substring(0, 64) : code, DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture)));
            if (lastErrors.Count > 20) lastErrors.RemoveAt(0);
        }
        Log.Debug("error", code);
    }

    // --- asynchronous sanitization -----------------------------------------------------

    private async Task WorkerAsync()
    {
        try
        {
            await foreach (RawExchange raw in pending.Reader.ReadAllAsync(cts.Token).ConfigureAwait(false))
            {
                Interlocked.Add(ref pendingBytes, -raw.HeldBytes);
                try { Process(raw); }
                finally { Interlocked.Decrement(ref inFlight); }
            }
        }
        catch (OperationCanceledException)
        {
            // stopping
        }
    }

    private void Process(RawExchange raw)
    {
        Exporter? exp = exporter;
        Enrollment? enr = enrollment;
        if (exp == null || enr == null || Volatile.Read(ref san) == null) return;
        long gen = Interlocked.Read(ref killGen);
        long egen = exp.Generation;
        try
        {
            SanitizeResult r = raw.Sanitizer.Run(raw.Build(), CaptureUtil.NowMs(), raw.Decision);
            if (r.Outcome == Outcome.NotSampled) return;
            if (r.Outcome == Outcome.TooLarge)
            {
                Interlocked.Increment(ref counters.SanitizerErrors);
                NoteError("event_too_large");
                return;
            }
            Policy p = raw.Sanitizer.Policy;
            string? json = EventBuilder.Build(r.Parts!, new EventMeta
            {
                PolicyId = p.PolicyId,
                PolicyVersion = p.Version,
                PolicyHash = p.Hash,
                SourceId = enr.SourceId,
                Inbound = raw.Inbound,
                TsMs = raw.TsMs,
                LatencyMs = raw.LatencyMs,
                Status = raw.Status,
                NetError = raw.NetError,
                TraceId = raw.TraceId,
                SpanId = raw.SpanId,
                ParentSpanId = raw.ParentSpanId,
            });
            if (json == null)
            {
                Interlocked.Increment(ref counters.SanitizerErrors);
                NoteError("event_invalid_or_too_large");
                return;
            }
            if (gen != Interlocked.Read(ref killGen) || Volatile.Read(ref san) == null)
            {
                // the kill switch arrived while this exchange was being sanitized
                Interlocked.Increment(ref counters.EventsDroppedQueue);
                return;
            }
            exp.Enqueue(new QueuedEvent { Json = json, TsMs = raw.TsMs, TraceId = raw.TraceId, SpanId = raw.SpanId, PolicyHash = p.Hash }, egen);
        }
        catch (Exception)
        {
            // An internal error never produces an event.
            Interlocked.Increment(ref counters.SanitizerErrors);
            NoteError("sanitizer_error");
        }
    }

    // --- lifecycle ----------------------------------------------------------------------

    private void StartInBackground()
    {
        startTask = Task.Run(() => StartAsync(cts.Token));
    }

    /// <summary>Installs the hooks and runs the first Fleet cycle. Never throws.</summary>
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        if (opts.Disabled) return;
        try
        {
            worker ??= Task.Run(WorkerAsync);
            observer ??= HttpDiagnosticsObserver.Install(this);
            string? svc = opts.ServiceName;
            if (string.IsNullOrEmpty(opts.EnrollUrl) || string.IsNullOrEmpty(svc))
            {
                NoteError("not_configured");
                return;
            }
            store = new StateStore(opts.StateDir ?? StateStore.DefaultDir(opts.EnrollUrl, svc)) { OnUntrusted = NoteError };
            if (!store.Prepare())
            {
                // A state directory we cannot trust (not ours, cannot be made 0700): never read from it. The state then lives
                // in a private temporary directory and the enrollment does not survive a restart.
                NoteError("state_dir_untrusted");
                store = new StateStore(Directory.CreateTempSubdirectory("traffic-twin-").FullName) { OnUntrusted = NoteError };
            }
            persisted = store.ReadJson<PersistedState>("state.json") ?? new PersistedState();
            LoadKeys();
            Enrollment? saved = store.ReadJson<Enrollment>("enrollment.json");
            string? savedKey = store.ReadText("client.key");
            if (saved != null && savedKey != null && saved.EnrollUrl == opts.EnrollUrl)
            {
                enrollment = saved;
                keyPem = savedKey;
            }
            else
            {
                await EnrollWithRetryAsync(cancellationToken).ConfigureAwait(false);
                if (enrollment == null) return;
            }
            Connect();
            // Re-verify the cached policy (its issued_seq may equal the last accepted one).
            string? cached = store.ReadText("policy.envelope.json");
            if (cached != null)
            {
                try { TryAccept(Plain.From(JsonParser.Parse(Encoding.UTF8.GetBytes(cached)), true), true, cached); }
                catch (Exception) { NoteError("policy_cache_invalid"); }
            }
            await HeartbeatAsync(cancellationToken).ConfigureAwait(false);
            await PollPolicyAsync(cancellationToken).ConfigureAwait(false);
            loops = Task.WhenAll(Loop(HeartbeatPeriod(), HeartbeatAsync), Loop(PollPeriod(), PollPolicyAsync));
        }
        catch (OperationCanceledException)
        {
            // stopping
        }
        catch (Exception e)
        {
            NoteError(e is FleetException fe ? fe.Code : "start_failed");
        }
        Recompute();
    }

    private TimeSpan HeartbeatPeriod() => opts.HeartbeatInterval ?? TimeSpan.FromSeconds(Math.Max(5, enrollment!.HeartbeatIntervalS));

    private TimeSpan PollPeriod() => opts.PolicyPollInterval ?? TimeSpan.FromSeconds(Math.Max(5, enrollment!.PolicyPollIntervalS));

    private async Task Loop(TimeSpan period, Func<CancellationToken, Task> fn)
    {
        try
        {
            while (!cts.IsCancellationRequested)
            {
                await Task.Delay(period, cts.Token).ConfigureAwait(false);
                try { await fn(cts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (cts.IsCancellationRequested) { throw; }
                catch (Exception) { NoteError("loop_error"); }
            }
        }
        catch (OperationCanceledException)
        {
            // stopping
        }
    }

    /// <summary>Waits for the first Fleet cycle (tests and graceful start-up scripts). Never throws.</summary>
    public async Task WaitStartedAsync()
    {
        Task? t = startTask;
        if (t != null)
        {
            try { await t.ConfigureAwait(false); }
            catch (Exception) { /* reported through the state */ }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (stopped) return;
        stopped = true;
        cts.Cancel();
        Volatile.Write(ref san, null);
        observer?.Dispose();
        pending.Writer.TryComplete();
        foreach (Task? t in new[] { startTask, loops, worker })
        {
            if (t == null) continue;
            try { await t.ConfigureAwait(false); }
            catch (Exception) { /* stopping */ }
        }
        if (exporter != null) await exporter.DisposeAsync().ConfigureAwait(false);
        mtls?.Dispose();
        clientCert?.Dispose();
        lock (CurrentGate)
        {
            if (ReferenceEquals(current, this)) current = null;
        }
        cts.Dispose();
    }

    /// <summary>Sanitizes what is pending and sends everything queued (tests, graceful shutdown).</summary>
    public async Task FlushAsync()
    {
        for (int i = 0; i < 2000 && Interlocked.Read(ref inFlight) > 0; i++) await Task.Delay(5).ConfigureAwait(false);
        if (exporter != null) await exporter.FlushAsync().ConfigureAwait(false);
    }

    public AgentStatus Status()
    {
        var q = exporter?.Size ?? (0, 0L);
        return new AgentStatus(state, Counters.Get(ref counters.ExchangesSeen), Counters.Get(ref counters.ExchangesSampled), Counters.Get(ref counters.EventsSent),
            Counters.Get(ref counters.EventsDroppedQueue), Counters.Get(ref counters.EventsRejected), Counters.Get(ref counters.SendErrors), Counters.Get(ref counters.SanitizerErrors), q.Item1, q.Item2);
    }

    /// <summary>Heartbeat state: starting | capturing | no_policy | policy_rejected | expired_policy | key_missing | key_mismatch | killed.</summary>
    public string State => state;

    private async Task EnrollWithRetryAsync(CancellationToken ct)
    {
        if (string.IsNullOrEmpty(opts.EnrollToken))
        {
            NoteError("enroll_token_missing");
            return;
        }
        TimeSpan delay = TimeSpan.FromSeconds(2);
        for (int attempt = 0; attempt < 8 && !ct.IsCancellationRequested; attempt++)
        {
            try
            {
                var (e, k) = await FleetClient.EnrollAsync(opts.EnrollUrl!, opts.EnrollToken!, new SourceInfo(opts.ServiceName!, (opts.Instance ?? Environment.MachineName)), opts.UseCsr,
                    ring?.Order, opts.RequestTimeout, ct).ConfigureAwait(false);
                enrollment = e;
                keyPem = k;
                store!.WriteText("client.key", k);
                store.WriteJson("enrollment.json", e);
                return;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                string code = ex is FleetException fe ? fe.Code : "enroll_failed";
                NoteError(code);
                // Token or identity errors will not fix themselves.
                if (ex is FleetException { Status: not null and < 500 }) return;
                if (code.Contains("pin", StringComparison.Ordinal) || code.Contains("root", StringComparison.Ordinal) || code.Contains("token", StringComparison.Ordinal) ||
                    code.Contains("chain", StringComparison.Ordinal) || code.Contains("bad_", StringComparison.Ordinal)) return;
            }
            try { await Task.Delay(delay, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
            delay = TimeSpan.FromSeconds(Math.Min(delay.TotalSeconds * 2, 300));
        }
    }

    private void Connect()
    {
        Enrollment e = enrollment!;
        var (leaf, extras) = FleetTls.LoadClientCertificate(e.ClientCert, keyPem);
        HttpClient client = FleetTls.MtlsClient(leaf, extras, e.CaChain, opts.RequestTimeout);
        HttpClient? oldClient = mtls;
        X509Certificate2? oldCert = clientCert;
        mtls = client;
        clientCert = leaf;
        if (fleet != null) fleet.SetClient(client);
        else fleet = new FleetClient(client, e.FleetUrl);
        if (exporter != null) exporter.SetTarget(client, e.IntakeUrl);
        else
        {
            exporter = new Exporter(client, e.IntakeUrl, e.ServiceName, e.SourceId, counters, NoteError, opts.ExportFlushInterval);
        }
        // Requests in flight on the old client get time to finish before it is disposed.
        if (oldClient != null || oldCert != null)
        {
            _ = Task.Delay(TimeSpan.FromSeconds(60)).ContinueWith(_ =>
            {
                oldClient?.Dispose();
                oldCert?.Dispose();
            }, TaskScheduler.Default);
        }
    }

    // --- keys ---------------------------------------------------------------------------

    private void LoadKeys()
    {
        string? text = opts.HmacKey;
        if (text == null && !string.IsNullOrEmpty(opts.HmacKeyFile))
        {
            try { text = File.ReadAllText(opts.HmacKeyFile, Encoding.UTF8); }
            catch (Exception) { text = null; }
        }
        try { ring = PolicyChecks.ParseKeyRing(text); }
        catch (RefusedException) { ring = null; }
    }

    private Dictionary<string, byte[]> SigningKeys()
    {
        var revoked = new HashSet<string>(persisted.RevokedKids, StringComparer.Ordinal);
        var m = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (SigningKey k in (enrollment?.PolicySigningKeys ?? new List<SigningKey>()).Concat(persisted.AddedKeys))
        {
            if (revoked.Contains(k.Kid) || m.ContainsKey(k.Kid)) continue;
            byte[]? pk = PolicyChecks.Ed25519PublicKey(k.PublicKey);
            if (pk != null) m[k.Kid] = pk;
        }
        return m;
    }

    private void Persist()
    {
        try { store?.WriteJson("state.json", persisted); }
        catch (Exception) { NoteError("state_write_failed"); }
    }

    // --- policy (policy.md 4) -----------------------------------------------------------

    private void TryAccept(object? envelope, bool fromCache, string rawText)
    {
        try
        {
            var v = PolicyChecks.VerifyEnvelope(envelope, SigningKeys(), true);
            var p = new Policy(v.Body) { Hash = v.Hash };
            if (policy != null && policy.Hash == p.Hash && !fromCache) return;
            PolicyChecks.CheckAcceptance(p, enrollment!.Group, CaptureUtil.NowMs(), persisted.LastIssuedSeq, persisted.MinIssuedSeq, allowEqualSeq: fromCache);
            if (switching) Log.Debug("info", "policy_changed: now issued_seq " + p.IssuedSeq.ToString(CultureInfo.InvariantCulture));
            policy = p;
            policyKid = ((envelope as Dictionary<string, object?>)?.GetValueOrDefault("signature") as Dictionary<string, object?>)?.GetValueOrDefault("kid") as string ?? "";
            rejected = null;
            switching = false;
            persisted.LastIssuedSeq = p.IssuedSeq;
            Persist();
            // The cache holds the signed envelope exactly as received; it is re-verified at start.
            if (!fromCache) store?.WriteText("policy.envelope.json", rawText);
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "cookie", "baggage" };
            if (p.Subject is { From: "header" } sj) names.Add(Utf8Util.AsciiLower(sj.Name));
            decisionNames = names;
        }
        catch (Exception e)
        {
            string code = e is RefusedException r ? r.Code : "policy_rejected";
            // hardening.md 2.2: a policy refused for the safety subset is reported as policy_unsafe.
            NoteError(e is RefusedException { Detail: var detail } && detail.StartsWith(PolicyChecks.UnsafeDetail, StringComparison.Ordinal) ? "policy_unsafe" : code);
            // Keep the previous policy if it is still valid; otherwise report the rejection.
            if (policy == null) rejected = code == "expired_policy" ? "expired_policy" : "policy_rejected";
        }
        Recompute();
    }

    private async Task PollPolicyAsync(CancellationToken ct)
    {
        await pollGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await PollPolicyOnceAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            pollGate.Release();
        }
    }

    private async Task PollPolicyOnceAsync(CancellationToken ct)
    {
        FleetClient? f = fleet;
        if (f == null || stopped) return;
        try
        {
            HttpReply r = await f.GetPolicyAsync(policy != null ? etag : null, ct).ConfigureAwait(false);
            if (r.Status == 304)
            {
                lastContact = CaptureUtil.NowMs();
            }
            else if (r.Status == 200)
            {
                lastContact = CaptureUtil.NowMs();
                object? env;
                try { env = Plain.From(JsonParser.Parse(r.Body), true); }
                catch (JsonException2)
                {
                    NoteError("policy_json");
                    if (policy == null) rejected = "policy_rejected";
                    Recompute();
                    return;
                }
                TryAccept(env, false, Encoding.UTF8.GetString(r.Body));
                if (policy != null && r.ETag != null) etag = r.ETag;
            }
            else if (r.Status == 404)
            {
                lastContact = CaptureUtil.NowMs();
                policy = null;
                rejected = "no_policy";
            }
            else if (r.Status == 403)
            {
                Revoke();
            }
            else
            {
                NoteError("policy_http_" + r.Status.ToString(CultureInfo.InvariantCulture));
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            NoteError("policy_network");
        }
        if (switching && policy == null)
        {
            // The newer policy announced by the heartbeat could not be fetched or accepted.
            switching = false;
            if (rejected == "starting")
            {
                rejected = "policy_rejected";
                NoteError("policy_below_min_issued_seq");
            }
        }
        Recompute();
    }

    // --- heartbeat -----------------------------------------------------------------------

    /// <summary>p50 and p99 (microseconds) of the time the capture hooks spent on the request path, over the last 1024 sampled or decided exchanges.</summary>
    public (long P50, long P99) OverheadUs()
    {
        long n = Math.Min(Interlocked.Read(ref overheadN), overhead.Length);
        if (n == 0) return (0, 0);
        var a = new long[n];
        Array.Copy(overhead, a, n);
        Array.Sort(a);
        long Q(double f) => (long)Math.Round(a[Math.Min(n - 1, (long)Math.Floor(f * n))] / 1000.0);
        return (Q(0.5), Q(0.99));
    }

    private async Task HeartbeatAsync(CancellationToken ct)
    {
        FleetClient? f = fleet;
        if (f == null || stopped) return;
        LoadKeys();
        Recompute();
        Policy? p = policy;
        var q = exporter?.Size ?? (0, 0L);
        var (p50, p99) = OverheadUs();
        var body = new JsonObject
        {
            ["source_id"] = enrollment!.SourceId,
            ["state"] = state,
            ["counters"] = new JsonObject
            {
                ["exchanges_seen"] = Counters.Get(ref counters.ExchangesSeen),
                ["exchanges_sampled"] = Counters.Get(ref counters.ExchangesSampled),
                ["events_sent"] = Counters.Get(ref counters.EventsSent),
                ["events_dropped_queue"] = Counters.Get(ref counters.EventsDroppedQueue),
                ["events_rejected"] = Counters.Get(ref counters.EventsRejected),
                ["send_errors"] = Counters.Get(ref counters.SendErrors),
                ["sanitizer_errors"] = Counters.Get(ref counters.SanitizerErrors),
            },
            ["overhead_us"] = new JsonObject { ["p50"] = p50, ["p99"] = p99 },
            ["queue"] = new JsonObject { ["events"] = q.Item1, ["bytes"] = q.Item2 },
            ["runtime"] = new JsonObject { ["lang"] = "dotnet", ["lang_version"] = Environment.Version.ToString() },
        };
        if (p != null) body["policy"] = new JsonObject { ["id"] = p.PolicyId, ["version"] = p.Version, ["issued_seq"] = p.IssuedSeq, ["hash"] = p.Hash };
        var errs = new JsonArray();
        lock (lastErrors)
        {
            foreach (var (code, at) in lastErrors.TakeLast(20)) errs.Add(new JsonObject { ["code"] = code, ["at"] = at });
        }
        body["last_errors"] = errs;
        // The kids of the policy signing keys trusted now: tt-core waits for them before it allows revoking an old key.
        var kids = new JsonArray();
        foreach (string kid in SigningKeys().Keys.OrderBy(x => x, StringComparer.Ordinal)) kids.Add(kid);
        body["signing_kids"] = kids;
        try
        {
            HttpReply r = await f.HeartbeatAsync(body.ToJsonString(), ct).ConfigureAwait(false);
            if (r.Status == 403) Revoke();
            else if (r.Status == 200)
            {
                using JsonDocument doc = JsonDocument.Parse(r.Body);
                ApplyHeartbeat(doc.RootElement);
            }
            else NoteError("heartbeat_http_" + r.Status.ToString(CultureInfo.InvariantCulture));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            NoteError("heartbeat_network");
        }
        Recompute();
    }

    private void ApplyHeartbeat(JsonElement j)
    {
        heartbeatOk = true;
        lastContact = CaptureUtil.NowMs();
        bool kill = j.TryGetProperty("kill", out var k) && k.ValueKind == JsonValueKind.True;
        if (kill != persisted.Kill)
        {
            persisted.Kill = kill;
            Persist();
        }
        if (kill) DropQueues();
        if (j.TryGetProperty("min_issued_seq", out var ms) && ms.ValueKind == JsonValueKind.Number && ms.TryGetInt64(out long min) && min >= 0)
        {
            if (min != persisted.MinIssuedSeq)
            {
                persisted.MinIssuedSeq = min;
                Persist();
            }
            if (policy != null && policy.IssuedSeq < min)
            {
                bool newer = j.TryGetProperty("policy_current", out var pc) && pc.ValueKind == JsonValueKind.Object &&
                    pc.TryGetProperty("hash", out var ph) && ph.ValueKind == JsonValueKind.String && ph.GetString() != policy.Hash &&
                    pc.TryGetProperty("issued_seq", out var ps) && ps.ValueKind == JsonValueKind.Number && ps.TryGetInt64(out long pseq) && pseq >= min;
                // The policy in use is superseded for good: capture stops at once (fail-closed).
                policy = null;
                if (newer)
                {
                    // A normal policy change: the newer policy is fetched right away (policy_current below).
                    switching = true;
                    rejected = "starting";
                    Log.Debug("info", "policy_superseded: fetching the newer policy");
                }
                else
                {
                    rejected = "policy_rejected";
                    NoteError("policy_below_min_issued_seq");
                }
                Recompute();
            }
        }
        overrideBp = j.TryGetProperty("sampling_override_bp", out var o) && o.ValueKind == JsonValueKind.Number && o.TryGetInt32(out int bp) && bp >= 0 && bp <= 10000 ? bp : null;
        // Revocations first (fleet-api, RT3-KEY-3): a key endorsed by a kid revoked in this very response is never pinned.
        if (j.TryGetProperty("revoke_signing_keys", out var rev) && rev.ValueKind == JsonValueKind.Array) RevokeSigningKeys(rev);
        if (j.TryGetProperty("add_signing_keys", out var add) && add.ValueKind == JsonValueKind.Array) AddSigningKeys(add);
        if (j.TryGetProperty("policy_current", out var cur) && cur.ValueKind == JsonValueKind.Object && cur.TryGetProperty("hash", out var h) &&
            h.ValueKind == JsonValueKind.String && h.GetString() != policy?.Hash)
        {
            _ = Task.Run(() => PollPolicyAsync(cts.Token));
        }
        if (j.TryGetProperty("renew_before", out var rb) && rb.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(rb.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var when) &&
            DateTimeOffset.UtcNow >= when)
        {
            _ = Task.Run(() => RenewAsync(cts.Token));
        }
    }

    private void RevokeSigningKeys(JsonElement list)
    {
        var rk = new HashSet<string>(persisted.RevokedKids, StringComparer.Ordinal);
        bool changed = false;
        foreach (JsonElement e in list.EnumerateArray())
        {
            if (e.ValueKind == JsonValueKind.String && rk.Add(e.GetString()!)) changed = true;
        }
        if (changed)
        {
            persisted.RevokedKids = rk.ToList();
            persisted.AddedKeys = persisted.AddedKeys.Where(k => !rk.Contains(k.Kid)).ToList();
            Persist();
        }
        if (policy != null && rk.Contains(policyKid))
        {
            policy = null;
            rejected = "policy_rejected";
            NoteError("policy_key_revoked");
        }
    }

    /// <summary>
    /// Pins the keys of add_signing_keys endorsed by a pinned, non-revoked key, in list order (an endorser comes before
    /// the key it endorses). tt-core repeats the whole list at every heartbeat: a kid already pinned with the same key is
    /// skipped silently; a revoked kid is never pinned again.
    /// </summary>
    private void AddSigningKeys(JsonElement list)
    {
        var known = SigningKeys();
        var revoked = new HashSet<string>(persisted.RevokedKids, StringComparer.Ordinal);
        var added = new List<SigningKey>(persisted.AddedKeys);
        bool changed = false;
        foreach (JsonElement item in list.EnumerateArray())
        {
            // Canonical codes (docs/spec/policy.md §3.1): malformed -> rejected; a kid pinned to other bytes ->
            // conflict; unknown/revoked endorser -> endorser_unknown; bad signature -> endorsement_invalid.
            if (item.ValueKind != JsonValueKind.Object) { NoteError("signing_key_rejected"); continue; }
            string kid = Prop(item, "kid"), alg = Prop(item, "alg"), pub = Prop(item, "public_key"), by = Prop(item, "endorsed_by"), endo = Prop(item, "endorsement");
            if (kid.Length == 0 || kid.Length > 64 || !kid.All(c => char.IsAsciiLetterOrDigit(c) || c == '.' || c == '_' || c == '-'))
            {
                NoteError("signing_key_rejected");
                continue;
            }
            if (revoked.Contains(kid)) continue;
            byte[]? raw = pub.Length == 0 ? null : Utf8Util.B64UrlDecodeStrict(pub);
            byte[]? sig = endo.Length == 0 ? null : Utf8Util.B64UrlDecodeStrict(endo);
            if (alg != "Ed25519" || by.Length == 0 || raw == null || raw.Length != 32 || sig == null || sig.Length != 64)
            {
                NoteError("signing_key_rejected");
                continue;
            }
            if (known.TryGetValue(kid, out byte[]? pinned))
            {
                if (!pinned.AsSpan().SequenceEqual(raw)) NoteError("signing_key_conflict");
                continue;
            }
            if (revoked.Contains(by) || !known.TryGetValue(by, out byte[]? endorser))
            {
                NoteError("signing_key_endorser_unknown");
                continue;
            }
            byte[] prefix = Utf8Util.Latin1("tt-fleet-key/v1\0" + kid + "\0");
            var msg = new byte[prefix.Length + raw.Length];
            prefix.CopyTo(msg, 0);
            raw.CopyTo(msg, prefix.Length);
            if (!Ed25519.Verify(endorser, msg, sig))
            {
                NoteError("signing_key_endorsement_invalid");
                continue;
            }
            added.Add(new SigningKey { Kid = kid, Alg = "Ed25519", PublicKey = pub });
            known[kid] = raw;
            changed = true;
        }
        if (!changed) return;
        persisted.AddedKeys = added;
        Persist();
    }

    private static string Prop(JsonElement o, string name) => o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private async Task RenewAsync(CancellationToken ct)
    {
        FleetClient? f = fleet;
        Enrollment? e = enrollment;
        if (f == null || e == null) return;
        try
        {
            var r = await f.RenewAsync(opts.UseCsr, e.ServiceName, ct).ConfigureAwait(false);
            if (r == null)
            {
                NoteError("renew_failed");
                return;
            }
            e.ClientCert = r.Value.Cert;
            if (r.Value.NotAfter != null) e.NotAfter = r.Value.NotAfter;
            keyPem = r.Value.KeyPem;
            store?.WriteText("client.key", keyPem);
            store?.WriteJson("enrollment.json", e);
            Connect();
        }
        catch (Exception)
        {
            NoteError("renew_network");
        }
    }

    private void Revoke()
    {
        persisted.Revoked = true;
        Persist();
        DropQueues();
        NoteError("source_revoked");
    }

    private void DropQueues()
    {
        Interlocked.Increment(ref killGen);
        while (pending.Reader.TryRead(out RawExchange? raw))
        {
            Interlocked.Add(ref pendingBytes, -raw.HeldBytes);
            Interlocked.Decrement(ref inFlight);
            Interlocked.Increment(ref counters.EventsDroppedQueue);
        }
        exporter?.Clear();
    }

    /// <summary>Recomputes the state and the capture gate.</summary>
    private void Recompute()
    {
        lock (stateGate)
        {
            long now = CaptureUtil.NowMs();
            Policy? p = policy;
            long maxAgeMs = (enrollment?.PolicyMaxAgeS ?? 86400) * 1000;
            string st;
            (string Kid, byte[] Key)? key = null;
            if (persisted.Kill || persisted.Revoked) st = "killed";
            else if (p == null) st = rejected ?? "no_policy";
            else if (!(now < p.NotAfter) || (lastContact > 0 && now - lastContact > maxAgeMs)) st = "expired_policy";
            else if (ring == null) st = "key_missing";
            else
            {
                try
                {
                    key = PolicyChecks.SelectKey(ring, p);
                    st = heartbeatOk ? "capturing" : "starting";
                }
                catch (RefusedException)
                {
                    st = "key_mismatch";
                }
            }
            // Capture only after a heartbeat in this process (kill switch and min_issued_seq known).
            if (st == "capturing" && key != null && p != null && lastContact > 0)
            {
                Sanitizer? cur = san;
                if (cur == null || !ReferenceEquals(cur.Policy, p) || cur.Kid != key.Value.Kid || !ReferenceEquals(cur.Key, key.Value.Key) || cur.RateOverrideBp != overrideBp)
                    Volatile.Write(ref san, new Sanitizer(p, key.Value.Kid, key.Value.Key, overrideBp));
            }
            else
            {
                if (st == "capturing") st = "starting";
                Volatile.Write(ref san, null);
            }
            if (st != state) Log.Debug("state", st);
            state = st;
        }
    }
}

internal static class Log
{
    public static volatile bool Enabled;

    /// <summary>Status and error codes only; never payload values.</summary>
    public static void Debug(string what, string code)
    {
        if (Enabled) Console.Error.WriteLine("[traffic-twin] " + what + ": " + code);
    }
}
