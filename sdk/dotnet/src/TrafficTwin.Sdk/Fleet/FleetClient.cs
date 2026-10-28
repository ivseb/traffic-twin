using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using TrafficTwin.Sdk.Capture;
using TrafficTwin.Sdk.Sanitizing;

namespace TrafficTwin.Sdk.Fleet;

internal sealed record SourceInfo(string ServiceName, string? Instance);

internal sealed record HttpReply(int Status, byte[] Body, string? ETag);

/// <summary>Fleet API client (api/fleet-api.v1.openapi.yaml): enrollment with a <c>tte_</c> token and CA pin, then mTLS calls.</summary>
internal sealed class FleetClient
{
    private HttpClient http;
    private readonly string fleetUrl;

    public FleetClient(HttpClient http, string fleetUrl)
    {
        this.http = http;
        this.fleetUrl = fleetUrl;
    }

    public void SetClient(HttpClient c) => http = c;

    private static bool IsHttps(string? v) => Uri.TryCreate(v, UriKind.Absolute, out Uri? u) && u.Scheme == Uri.UriSchemeHttps;

    private static readonly Regex SourceIdRe = Re.Full("src-[0-9A-Za-z]{1,32}");
    private static readonly Regex GroupRe = Re.Full("[a-z0-9][a-z0-9-]{0,62}");
    private static readonly Regex ServiceRe = Re.Full("[a-z0-9][a-z0-9._-]{0,62}");
    private static readonly Regex KidRe = Re.Full("[A-Za-z0-9._-]{1,64}");
    private static readonly Regex KeyRe = Re.Full("[A-Za-z0-9_-]{43}");

    /// <summary>Enrolls with a token. Returns the enrollment and the private key PEM (generated locally when <paramref name="useCsr"/>).</summary>
    public static async Task<(Enrollment Enrollment, string KeyPem)> EnrollAsync(string enrollUrl, string token, SourceInfo source, bool useCsr, IEnumerable<string>? hmacKids, TimeSpan timeout, CancellationToken ct)
    {
        string? pin = FleetTls.TokenPin(token);
        if (pin == null) throw new FleetException("enroll_token_malformed");
        if (!Uri.TryCreate(enrollUrl, UriKind.Absolute, out Uri? baseUri) || baseUri.Scheme != Uri.UriSchemeHttps) throw new FleetException("enroll_url_not_https");

        string keyPem = "";
        var body = new JsonObject { ["token"] = token };
        var src = new JsonObject
        {
            ["kind"] = SdkInfo.SourceKind,
            ["version"] = SdkInfo.Version,
            ["service_name"] = source.ServiceName,
            ["runtime"] = new JsonObject
            {
                ["lang"] = "dotnet",
                ["lang_version"] = Environment.Version.ToString(),
                ["os"] = OsName(),
                ["arch"] = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
            },
        };
        if (source.Instance != null) src["instance"] = source.Instance.Length > 128 ? source.Instance.Substring(0, 128) : source.Instance;
        if (hmacKids != null)
        {
            var kids = new JsonArray();
            foreach (string k in hmacKids)
            {
                if (kids.Count >= 8) break;
                kids.Add(k);
            }
            if (kids.Count > 0) src["hmac_kids"] = kids;
        }
        body["source"] = src;
        if (useCsr)
        {
            var (k, csr) = FleetTls.GenerateCsr(source.ServiceName);
            keyPem = k;
            body["csr"] = csr;
        }

        using HttpClient pinned = FleetTls.PinnedClient(pin, timeout);
        HttpResponseMessage res;
        byte[] resBody;
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, new Uri(baseUri, "/fleet/v1/enroll")) { Content = JsonContent(body.ToJsonString()) };
            req.Options.Set(CaptureUtil.InternalKey, true);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(timeout);
            res = await pinned.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            resBody = await ReadBoundedAsync(res, 1 << 20, deadline.Token).ConfigureAwait(false);
        }
        catch (HttpRequestException e) when (e.InnerException is System.Security.Authentication.AuthenticationException || e.HttpRequestError == HttpRequestError.SecureConnectionError)
        {
            throw new FleetException("enroll_pin_mismatch");
        }
        catch (Exception e) when (e is not FleetException && e is not OperationCanceledException)
        {
            throw new FleetException("enroll_network");
        }
        int status = (int)res.StatusCode;
        res.Dispose();
        if (status != 201 && status != 200) throw new FleetException("enroll_http_" + status.ToString(CultureInfo.InvariantCulture), status);
        JsonElement j;
        try
        {
            using var doc = JsonDocument.Parse(resBody);
            j = doc.RootElement.Clone();
        }
        catch (JsonException)
        {
            throw new FleetException("enroll_bad_response");
        }
        if (j.ValueKind != JsonValueKind.Object) throw new FleetException("enroll_bad_response");
        if (!useCsr)
        {
            if (!j.TryGetProperty("client_key", out var ck) || ck.ValueKind != JsonValueKind.String) throw new FleetException("enroll_no_key");
            keyPem = ck.GetString()!;
        }
        var e2 = new Enrollment
        {
            SourceId = Str(j, "source_id"),
            Group = Str(j, "group"),
            ServiceName = Str(j, "service_name"),
            ClientCert = Str(j, "client_cert"),
            CaChain = Str(j, "ca_chain"),
            NotAfter = j.TryGetProperty("not_after", out var na) && na.ValueKind == JsonValueKind.String ? na.GetString() : null,
            IntakeUrl = Str(j, "intake_url"),
            FleetUrl = Str(j, "fleet_url"),
            PolicyMaxAgeS = Int(j, "policy_max_age_s", 86400),
            HeartbeatIntervalS = Int(j, "heartbeat_interval_s", 30),
            PolicyPollIntervalS = Int(j, "policy_poll_interval_s", 60),
            EnrollUrl = enrollUrl,
            Pin = pin,
        };
        if (j.TryGetProperty("policy_signing_keys", out var keys) && keys.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement k in keys.EnumerateArray())
            {
                string kid = Str(k, "kid"), alg = Str(k, "alg"), pk = Str(k, "public_key");
                if (KidRe.IsMatch(kid) && alg == "Ed25519" && KeyRe.IsMatch(pk)) e2.PolicySigningKeys.Add(new SigningKey { Kid = kid, Alg = "Ed25519", PublicKey = pk });
            }
        }
        if (!SourceIdRe.IsMatch(e2.SourceId)) throw new FleetException("enroll_bad_source_id");
        if (!GroupRe.IsMatch(e2.Group)) throw new FleetException("enroll_bad_group");
        if (!ServiceRe.IsMatch(e2.ServiceName)) throw new FleetException("enroll_bad_service_name");
        if (FleetTls.PemBlocks(e2.ClientCert, "CERTIFICATE").Count == 0) throw new FleetException("enroll_bad_cert");
        bool pinned2 = false;
        foreach (byte[] der in FleetTls.PemBlocks(e2.CaChain, "CERTIFICATE"))
        {
            if (FleetTls.PinOf(der) == pin) pinned2 = true;
        }
        if (!pinned2) throw new FleetException("enroll_chain_without_pinned_root");
        if (e2.PolicySigningKeys.Count == 0) throw new FleetException("enroll_no_signing_keys");
        if (!IsHttps(e2.IntakeUrl) || !IsHttps(e2.FleetUrl)) throw new FleetException("enroll_bad_urls");
        return (e2, keyPem);
    }

    private static string OsName() => OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsMacOS() ? "darwin" : OperatingSystem.IsLinux() ? "linux" : "other";

    private static string Str(JsonElement o, string name) => o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static long Int(JsonElement o, string name, long d) => o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out long n) ? n : d;

    private static ByteArrayContent JsonContent(string json)
    {
        var c = new ByteArrayContent(new UTF8Encoding(false).GetBytes(json));
        c.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return c;
    }

    private Uri Url(string path) => new(new Uri(fleetUrl), path);

    /// <summary>Largest answer accepted from the Fleet API per call (the policy; the others are small).</summary>
    internal const long MaxBody = 8 << 20;

    /// <summary>
    /// Reads the body of <paramref name="res"/> up to <paramref name="max"/> bytes: the read ends with
    /// <see cref="FleetException"/> at max+1 bytes (never buffered whole, the connection is released by the disposal of
    /// the response) and, because <paramref name="ct"/> is a deadline-linked token, does not outlive the exchange timeout.
    /// A <c>Content-Encoding</c> is not requested and not accepted.
    /// </summary>
    internal static async Task<byte[]> ReadBoundedAsync(HttpResponseMessage res, long max, CancellationToken ct)
    {
        if (res.Content.Headers.ContentLength is long declared && declared > max) throw new FleetException("fleet_response_too_large");
        if (res.Content.Headers.ContentEncoding.Count > 0) throw new FleetException("fleet_response_encoding");
        await using var s = await res.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var ms = new System.IO.MemoryStream();
        var buf = new byte[8192];
        int n;
        while ((n = await s.ReadAsync(buf, ct).ConfigureAwait(false)) > 0)
        {
            if (ms.Length + n > max) throw new FleetException("fleet_response_too_large");
            ms.Write(buf, 0, n);
        }
        return ms.ToArray();
    }

    /// <summary>Deadline of a whole exchange (headers and body): the client's timeout, 30 s when it has none.</summary>
    private static TimeSpan Deadline(HttpClient c) => c.Timeout > TimeSpan.Zero && c.Timeout != Timeout.InfiniteTimeSpan ? c.Timeout : TimeSpan.FromSeconds(30);

    private async Task<HttpReply> SendAsync(HttpMethod method, string path, string? body, string? ifNoneMatch, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(method, Url(path));
        req.Options.Set(CaptureUtil.InternalKey, true);
        if (body != null) req.Content = JsonContent(body);
        if (ifNoneMatch != null) req.Headers.TryAddWithoutValidation("If-None-Match", ifNoneMatch);
        // HttpClient.Timeout does not cover the body once the headers are read: one deadline for the whole exchange.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(Deadline(http));
        using HttpResponseMessage res = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
        byte[] bytes = await ReadBoundedAsync(res, MaxBody, deadline.Token).ConfigureAwait(false);
        string? etag = res.Headers.ETag?.ToString();
        return new HttpReply((int)res.StatusCode, bytes, etag);
    }

    public Task<HttpReply> HeartbeatAsync(string json, CancellationToken ct) => SendAsync(HttpMethod.Post, "/fleet/v1/heartbeat", json, null, ct);

    public Task<HttpReply> GetPolicyAsync(string? etag, CancellationToken ct) => SendAsync(HttpMethod.Get, "/fleet/v1/policy", null, etag, ct);

    /// <summary>Certificate renewal. Returns the new certificate PEM, the private key PEM and the expiry, or null on any failure.</summary>
    public async Task<(string Cert, string KeyPem, string? NotAfter)?> RenewAsync(bool useCsr, string commonName, CancellationToken ct)
    {
        string? keyPem = null;
        var body = new JsonObject();
        if (useCsr)
        {
            var (k, csr) = FleetTls.GenerateCsr(commonName);
            keyPem = k;
            body["csr"] = csr;
        }
        HttpReply r = await SendAsync(HttpMethod.Post, "/fleet/v1/renew", body.ToJsonString(), null, ct).ConfigureAwait(false);
        if (r.Status != 200) return null;
        try
        {
            using var doc = JsonDocument.Parse(r.Body);
            JsonElement j = doc.RootElement;
            if (j.ValueKind != JsonValueKind.Object || !j.TryGetProperty("client_cert", out var c) || c.ValueKind != JsonValueKind.String) return null;
            if (!useCsr) keyPem = j.TryGetProperty("client_key", out var kk) && kk.ValueKind == JsonValueKind.String ? kk.GetString() : null;
            if (keyPem == null) return null;
            return (c.GetString()!, keyPem, j.TryGetProperty("not_after", out var na) && na.ValueKind == JsonValueKind.String ? na.GetString() : null);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
