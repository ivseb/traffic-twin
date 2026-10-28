using System;
using System.Net.Http;
using System.Threading.Tasks;
using TrafficTwin.Sdk.Fleet;
using TrafficTwin.Sdk.Tests.Helpers;
using Xunit;

namespace TrafficTwin.Sdk.Tests;

public class Ed25519SignerTests
{
    [Fact]
    public void KeyDerivationMatchesRfc8032Test1()
    {
        byte[] seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        Assert.Equal("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", Convert.ToHexString(TestEd25519.PublicKey(seed)).ToLowerInvariant());
        Assert.Equal(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            Convert.ToHexString(TestEd25519.Sign(seed, Array.Empty<byte>())).ToLowerInvariant());
    }
}

public class FakeCoreSmokeTests
{
    [Fact]
    public async Task EnrollsOverPinnedTlsAndServesPolicy()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        var (enr, key) = await FleetClient.EnrollAsync(core.BaseUrl, core.Token, new SourceInfo("shop-api", "pod-1"), true, new[] { "k1" }, TimeSpan.FromSeconds(10), default);
        Assert.StartsWith("src-", enr.SourceId);
        Assert.Contains("BEGIN PRIVATE KEY", key);
        var (leaf, extras) = FleetTls.LoadClientCertificate(enr.ClientCert, key);
        using HttpClient mtls = FleetTls.MtlsClient(leaf, extras, enr.CaChain, TimeSpan.FromSeconds(10));
        var fc = new FleetClient(mtls, enr.FleetUrl);
        var hb = await fc.HeartbeatAsync("{\"source_id\":\"" + enr.SourceId + "\",\"state\":\"starting\",\"counters\":{}}", default);
        Assert.Equal(200, hb.Status);
        var pol = await fc.GetPolicyAsync(null, default);
        Assert.Equal(200, pol.Status);
        var again = await fc.GetPolicyAsync(pol.ETag, default);
        Assert.Equal(304, again.Status);
    }

    [Fact]
    public async Task WrongPinIsRefused()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        using var other = new TestPki("another root");
        string badToken = "tte_" + new string('a', 32) + "." + other.Pin;
        var ex = await Assert.ThrowsAsync<FleetException>(() => FleetClient.EnrollAsync(core.BaseUrl, badToken, new SourceInfo("shop-api", null), true, null, TimeSpan.FromSeconds(10), default));
        Assert.Equal("enroll_pin_mismatch", ex.Code);
    }

    [Fact]
    public async Task ServerThatDoesNotPresentTheRootIsRefused()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(), includeRoot: false);
        var ex = await Assert.ThrowsAsync<FleetException>(() => FleetClient.EnrollAsync(core.BaseUrl, core.Token, new SourceInfo("shop-api", null), true, null, TimeSpan.FromSeconds(10), default));
        Assert.Equal("enroll_pin_mismatch", ex.Code);
    }

    [Fact]
    public async Task MtlsIsRequiredForTheOtherEndpoints()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        // A client that trusts the root (through the pinned path) but has no certificate.
        var handler = new SocketsHttpHandler();
        handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        using var http = new HttpClient(handler);
        var res = await http.GetAsync(core.BaseUrl + "/fleet/v1/policy");
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, res.StatusCode);
    }
}
