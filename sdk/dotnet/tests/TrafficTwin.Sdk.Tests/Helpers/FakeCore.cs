using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TrafficTwin.Sdk.Fleet;
using TrafficTwin.Sdk.Sanitizing;

namespace TrafficTwin.Sdk.Tests.Helpers;

/// <summary>
/// A fake tt-core on a REAL Kestrel listener: one TLS port serving the Fleet source endpoints (enroll without a client
/// certificate, everything else with a verified one) and the OTLP/HTTP JSON intake, with the root in the presented chain.
/// </summary>
internal sealed class FakeCore : IAsyncDisposable
{
    public TestPki Pki { get; }
    public string BaseUrl { get; private set; } = "";
    public string Token { get; }
    public (byte[] Seed, byte[] Public) Signer { get; } = TestEd25519.NewKey();

    public ConcurrentQueue<string> Events { get; } = new();
    public ConcurrentQueue<string> OtlpRequests { get; } = new();
    public ConcurrentQueue<JsonObject> Heartbeats { get; } = new();
    public ConcurrentQueue<JsonObject> Enrollments { get; } = new();
    public int PolicyFetches;
    public int Renewals;
    public volatile bool Kill;
    public long MinIssuedSeq;
    public int? SamplingOverrideBp;
    public int FailLogs;
    public int RevokeSource;           // 1: heartbeat and policy answer 403
    public int HeartbeatCount;
    public volatile int HeartbeatDelayMs;
    public volatile bool AskRenewal;
    public string? PolicyEnvelope;
    public Dictionary<string, object?>? PolicyBody;
    public JsonArray? AddSigningKeys;
    public JsonArray? RevokeSigningKeys;
    /// <summary>Held while answering a heartbeat: set AddSigningKeys and RevokeSigningKeys together under it to put both in one response.</summary>
    public readonly object SigningKeysLock = new();
    public string Group = "shop";
    public string? FixedServiceName;
    public bool IncludeRootInChain = true;
    public readonly ConcurrentQueue<string> LogContentTypes = new();

    private WebApplication app = null!;

    private FakeCore(TestPki pki)
    {
        Pki = pki;
        Token = "tte_" + Utf8Util.B64UrlNoPad(RandomNumberGenerator.GetBytes(24)) + "." + pki.Pin;
    }

    public static async Task<FakeCore> StartAsync(Dictionary<string, object?>? policy = null, TestPki? pki = null, bool includeRoot = true)
    {
        var core = new FakeCore(pki ?? new TestPki()) { IncludeRootInChain = includeRoot };
        if (policy != null) core.SetPolicy(policy);
        await core.RunAsync().ConfigureAwait(false);
        return core;
    }

    public void SetPolicy(Dictionary<string, object?> body)
    {
        PolicyBody = body;
        PolicyEnvelope = PolicyFactory.Envelope(body, Signer.Seed);
    }

    /// <summary>Signs the policy with another key (rotation tests).</summary>
    public void SetPolicyWith(Dictionary<string, object?> body, byte[] seed, string kid)
    {
        PolicyBody = body;
        PolicyEnvelope = PolicyFactory.Envelope(body, seed, kid);
    }

    public string SigningKeyB64 => Utf8Util.B64UrlNoPad(Signer.Public);

    private async Task RunAsync()
    {
        var b = WebApplication.CreateBuilder();
        b.Logging.ClearProviders();
        var ctxTls = Pki.ServerContext(IncludeRootInChain);
        b.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0, lo => lo.UseHttps(h =>
        {
            h.ServerCertificate = Pki.Server;
            h.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
            h.ClientCertificateValidation = (_, _, _) => true;
            h.OnAuthenticate = (_, ssl) => ssl.ServerCertificateContext = ctxTls;
        })));
        app = b.Build();
        app.Run(Handle);
        await app.StartAsync().ConfigureAwait(false);
        string addr = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        BaseUrl = addr.Replace("127.0.0.1", "127.0.0.1");
    }

    private bool ClientAuthorized(HttpContext ctx)
    {
        X509Certificate2? c = ctx.Connection.ClientCertificate;
        if (c == null) return false;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(Pki.Root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(c);
    }

    private static async Task Json(HttpContext ctx, int status, string json, params (string, string)[] headers)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json";
        foreach (var (k, v) in headers) ctx.Response.Headers[k] = v;
        await ctx.Response.WriteAsync(json).ConfigureAwait(false);
    }

    private async Task Handle(HttpContext ctx)
    {
        string path = ctx.Request.Path.Value ?? "";
        using var ms = new MemoryStream();
        await ctx.Request.Body.CopyToAsync(ms).ConfigureAwait(false);
        byte[] body = ms.ToArray();
        if (path == "/fleet/v1/enroll" && ctx.Request.Method == "POST")
        {
            var j = JsonNode.Parse(body)!.AsObject();
            if ((string?)j["token"] != Token) { await Json(ctx, 401, "{\"code\":\"token\",\"message\":\"unknown token\"}"); return; }
            Enrollments.Enqueue(j);
            string sourceId = "src-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant();
            string svc = FixedServiceName ?? (string)j["source"]!["service_name"]!;
            string clientCert;
            string? clientKey = null;
            if (j["csr"] is JsonNode csr) clientCert = Pki.IssueFromCsr((string)csr!, sourceId);
            else (clientCert, clientKey) = Pki.IssueWithKey(sourceId);
            var resp = new JsonObject
            {
                ["source_id"] = sourceId,
                ["group"] = Group,
                ["service_name"] = svc,
                ["client_cert"] = clientCert,
                ["ca_chain"] = Pki.RootPem,
                ["policy_signing_keys"] = new JsonArray(new JsonObject { ["kid"] = PolicyFactory.SigningKid, ["alg"] = "Ed25519", ["public_key"] = SigningKeyB64 }),
                ["intake_url"] = BaseUrl + "/v1/logs",
                ["fleet_url"] = BaseUrl,
                ["policy_max_age_s"] = 86400,
                ["heartbeat_interval_s"] = 30,
                ["policy_poll_interval_s"] = 60,
            };
            if (clientKey != null) resp["client_key"] = clientKey;
            await Json(ctx, 201, resp.ToJsonString());
            return;
        }
        if (!ClientAuthorized(ctx)) { await Json(ctx, 401, "{\"code\":\"mtls\",\"message\":\"client certificate required\"}"); return; }
        if (path == "/fleet/v1/heartbeat" && ctx.Request.Method == "POST")
        {
            if (Volatile.Read(ref RevokeSource) == 1) { await Json(ctx, 403, "{\"code\":\"revoked\",\"message\":\"revoked\"}"); return; }
            if (HeartbeatDelayMs > 0) await Task.Delay(HeartbeatDelayMs);
            Interlocked.Increment(ref HeartbeatCount);
            Heartbeats.Enqueue(JsonNode.Parse(body)!.AsObject());
            var r = new JsonObject { ["next_heartbeat_s"] = 30, ["kill"] = Kill, ["min_issued_seq"] = Interlocked.Read(ref MinIssuedSeq) };
            // As tt-core: the policy the group runs now (the source fetches it when it differs).
            string? envText = PolicyEnvelope;
            if (envText != null)
            {
                var env = JsonNode.Parse(envText)!;
                r["policy_current"] = new JsonObject
                {
                    ["policy_id"] = env["policy_id"]!.GetValue<string>(),
                    ["version"] = env["version"]!.GetValue<long>(),
                    ["issued_seq"] = env["issued_seq"]!.GetValue<long>(),
                    ["hash"] = env["hash"]!.GetValue<string>(),
                };
            }
            if (SamplingOverrideBp.HasValue) r["sampling_override_bp"] = SamplingOverrideBp.Value;
            if (AskRenewal) r["renew_before"] = DateTimeOffset.UtcNow.AddMinutes(-1).ToString("o");
            lock (SigningKeysLock)
            {
                if (AddSigningKeys != null) r["add_signing_keys"] = JsonNode.Parse(AddSigningKeys.ToJsonString());
                if (RevokeSigningKeys != null) r["revoke_signing_keys"] = JsonNode.Parse(RevokeSigningKeys.ToJsonString());
            }
            await Json(ctx, 200, r.ToJsonString());
            return;
        }
        if (path == "/fleet/v1/policy" && ctx.Request.Method == "GET")
        {
            if (Volatile.Read(ref RevokeSource) == 1) { await Json(ctx, 403, "{}"); return; }
            Interlocked.Increment(ref PolicyFetches);
            if (PolicyEnvelope == null) { ctx.Response.StatusCode = 404; return; }
            string etag = "\"" + ((JsonNode.Parse(PolicyEnvelope)!)["hash"]!.GetValue<string>()) + "\"";
            if (ctx.Request.Headers.IfNoneMatch.ToString() == etag) { ctx.Response.StatusCode = 304; return; }
            await Json(ctx, 200, PolicyEnvelope, ("ETag", etag));
            return;
        }
        if (path == "/fleet/v1/renew" && ctx.Request.Method == "POST")
        {
            Interlocked.Increment(ref Renewals);
            var j = body.Length > 0 ? JsonNode.Parse(body)!.AsObject() : new JsonObject();
            string sid = "src-renewed";
            string cert;
            string? key = null;
            if (j["csr"] is JsonNode csr) cert = Pki.IssueFromCsr((string)csr!, sid);
            else (cert, key) = Pki.IssueWithKey(sid);
            var resp = new JsonObject { ["client_cert"] = cert, ["not_after"] = DateTimeOffset.UtcNow.AddDays(7).ToString("o") };
            if (key != null) resp["client_key"] = key;
            await Json(ctx, 200, resp.ToJsonString());
            return;
        }
        if (path == "/v1/logs" && ctx.Request.Method == "POST")
        {
            LogContentTypes.Enqueue(ctx.Request.ContentType ?? "");
            if (Interlocked.Decrement(ref FailLogs) >= 0) { ctx.Response.Headers["Retry-After"] = "0"; await Json(ctx, 503, "{}"); return; }
            string text = Encoding.UTF8.GetString(body);
            OtlpRequests.Enqueue(text);
            using var doc = JsonDocument.Parse(text);
            foreach (var rl in doc.RootElement.GetProperty("resourceLogs").EnumerateArray())
                foreach (var sl in rl.GetProperty("scopeLogs").EnumerateArray())
                    foreach (var lr in sl.GetProperty("logRecords").EnumerateArray())
                        Events.Enqueue(lr.GetProperty("body").GetProperty("stringValue").GetString()!);
            await Json(ctx, 200, "{}");
            return;
        }
        ctx.Response.StatusCode = 404;
    }

    /// <summary>Waits until at least <paramref name="n"/> events arrived.</summary>
    public async Task<List<string>> WaitEventsAsync(int n, int timeoutMs = 15000)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            if (Events.Count >= n) break;
            await Task.Delay(20).ConfigureAwait(false);
        }
        return Events.ToList();
    }

    public async ValueTask DisposeAsync()
    {
        await app.StopAsync().ConfigureAwait(false);
        await app.DisposeAsync().ConfigureAwait(false);
        Pki.Dispose();
    }
}
