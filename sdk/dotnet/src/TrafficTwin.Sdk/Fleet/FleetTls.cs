using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using TrafficTwin.Sdk.Sanitizing;

namespace TrafficTwin.Sdk.Fleet;

public sealed class FleetException : Exception
{
    public string Code { get; }
    public int? Status { get; }

    public FleetException(string code, int? status = null) : base(code)
    {
        Code = code;
        Status = status;
    }
}

/// <summary>TLS building blocks of the Fleet client: pinned enrollment channel, mTLS channel, CSR, PEM.</summary>
internal static class FleetTls
{
    public static readonly Regex TokenRe = Re.Full("tte_[A-Za-z0-9_-]{32,128}\\.([A-Za-z0-9_-]{43})");

    /// <summary>Extracts the CA pin from an enrollment token.</summary>
    public static string? TokenPin(string token)
    {
        Match m = TokenRe.Match(token);
        return m.Success ? m.Groups[1].Value : null;
    }

    /// <summary>base64url(SHA-256(DER)) of a certificate (the pin of the enrollment token).</summary>
    public static string PinOf(byte[] der) => Utf8Util.B64UrlNoPad(SHA256.HashData(der));

    public static List<byte[]> PemBlocks(string pem, string label)
    {
        var res = new List<byte[]>();
        var re = new Regex("-----BEGIN " + Regex.Escape(label) + "-----([A-Za-z0-9+/=\\s]+?)-----END " + Regex.Escape(label) + "-----", RegexOptions.CultureInvariant);
        foreach (Match m in re.Matches(pem))
        {
            try { res.Add(Convert.FromBase64String(Regex.Replace(m.Groups[1].Value, "\\s+", ""))); }
            catch (FormatException) { /* skip */ }
        }
        return res;
    }

    public static bool IsSelfSigned(X509Certificate2 c) => c.SubjectName.RawData.AsSpan().SequenceEqual(c.IssuerName.RawData);

    public static bool IsCa(X509Certificate2 c)
    {
        foreach (X509Extension e in c.Extensions)
        {
            if (e is X509BasicConstraintsExtension bc) return bc.CertificateAuthority;
        }
        return false;
    }

    private static bool BuildWithTrust(X509Certificate2 leaf, X509Certificate2Collection roots, IEnumerable<X509Certificate2> extra)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        foreach (var x in extra) chain.ChainPolicy.ExtraStore.Add(x);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        return chain.Build(leaf);
    }

    private static List<X509Certificate2> Presented(X509Chain chain)
    {
        var l = new List<X509Certificate2>();
        foreach (X509ChainElement e in chain.ChainElements) l.Add(e.Certificate);
        return l;
    }

    /// <summary>
    /// Enrollment channel: trusts nothing in advance. The server must present its chain up to the ROOT (tt-core includes it);
    /// that root must be a self-signed CA whose SHA-256 matches the pin of the token, and the server certificate must chain to it
    /// and match the host name. The root is then the only trust anchor of this connection.
    /// </summary>
    public static HttpClient PinnedClient(string pin, TimeSpan timeout)
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            PooledConnectionLifetime = TimeSpan.FromSeconds(30),
            ConnectTimeout = timeout,
        };
        handler.SslOptions.RemoteCertificateValidationCallback = (_, cert, chain, errors) =>
        {
            if (cert == null || chain == null) return false;
            if ((errors & (SslPolicyErrors.RemoteCertificateNotAvailable | SslPolicyErrors.RemoteCertificateNameMismatch)) != 0) return false;
            var presented = Presented(chain);
            if (presented.Count == 0) return false;
            X509Certificate2 top = presented[presented.Count - 1];
            if (!IsSelfSigned(top) || !IsCa(top)) return false;
            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(PinOf(top.RawData)), Encoding.ASCII.GetBytes(pin))) return false;
            using var leaf = new X509Certificate2(cert);
            return BuildWithTrust(leaf, new X509Certificate2Collection(top), presented);
        };
        return new HttpClient(handler, disposeHandler: true) { Timeout = timeout };
    }

    /// <summary>The roots (self-signed) and the intermediates of a PEM CA chain.</summary>
    public static (X509Certificate2Collection Roots, List<X509Certificate2> Intermediates) ParseChain(string caChainPem)
    {
        var roots = new X509Certificate2Collection();
        var inter = new List<X509Certificate2>();
        foreach (byte[] der in PemBlocks(caChainPem, "CERTIFICATE"))
        {
            var c = new X509Certificate2(der);
            if (IsSelfSigned(c)) roots.Add(c);
            else inter.Add(c);
        }
        return (roots, inter);
    }

    /// <summary>Client certificate (leaf with private key) and the extra certificates sent with it.</summary>
    public static (X509Certificate2 Leaf, List<X509Certificate2> Extras) LoadClientCertificate(string certPem, string keyPem)
    {
        var all = new X509Certificate2Collection();
        all.ImportFromPem(certPem);
        if (all.Count == 0) throw new FleetException("enroll_bad_cert");
        X509Certificate2 leaf = X509Certificate2.CreateFromPem(certPem, keyPem);
        if (OperatingSystem.IsWindows())
        {
            // SChannel needs a persisted key: round-trip through PFX.
            var tmp = leaf;
            leaf = new X509Certificate2(tmp.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.Exportable);
            tmp.Dispose();
        }
        var extras = new List<X509Certificate2>();
        for (int i = 1; i < all.Count; i++) extras.Add(all[i]);
        return (leaf, extras);
    }

    /// <summary>
    /// mTLS channel for the intake and Fleet calls. Trust anchors: the CA chain received over the pinned channel (and only it).
    /// The server certificate must chain to it and match the host name.
    /// </summary>
    public static HttpClient MtlsClient(X509Certificate2 clientCert, IEnumerable<X509Certificate2> clientExtras, string caChainPem, TimeSpan timeout)
    {
        var (roots, inter) = ParseChain(caChainPem);
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectTimeout = timeout,
            MaxConnectionsPerServer = 4,
        };
        var extraCollection = new X509Certificate2Collection();
        foreach (var x in clientExtras) extraCollection.Add(x);
        handler.SslOptions.ClientCertificateContext = SslStreamCertificateContext.Create(clientCert, extraCollection, offline: true);
        handler.SslOptions.RemoteCertificateValidationCallback = (_, cert, chain, errors) =>
        {
            if (cert == null || chain == null || roots.Count == 0) return false;
            if ((errors & (SslPolicyErrors.RemoteCertificateNotAvailable | SslPolicyErrors.RemoteCertificateNameMismatch)) != 0) return false;
            var extra = new List<X509Certificate2>(inter);
            extra.AddRange(Presented(chain));
            using var leaf = new X509Certificate2(cert);
            return BuildWithTrust(leaf, roots, extra);
        };
        return new HttpClient(handler, disposeHandler: true) { Timeout = timeout };
    }

    /// <summary>A new ECDSA P-256 key and the PKCS#10 request for it (the private key never leaves the process).</summary>
    public static (string KeyPem, string CsrPem) GenerateCsr(string commonName)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(new X500DistinguishedName("CN=" + commonName), key, HashAlgorithmName.SHA256);
        return (key.ExportPkcs8PrivateKeyPem(), req.CreateSigningRequestPem());
    }
}
