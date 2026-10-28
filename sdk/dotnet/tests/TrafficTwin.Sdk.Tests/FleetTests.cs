using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using TrafficTwin.Sdk.Sanitizing;
using TrafficTwin.Sdk.Tests.Helpers;
using Xunit;

namespace TrafficTwin.Sdk.Tests;

/// <summary>Source behaviour of policy.md 4 and fleet-api: fail closed, heartbeat first, kill switch, rotation.</summary>
public class FleetTests
{
    private static async Task<int> EventCount(FakeCore core, Sut sut, int settleMs = 300)
    {
        await sut.Agent!.FlushAsync();
        await Task.Delay(settleMs);
        return core.Events.Count;
    }

    [Fact]
    public async Task NothingIsCapturedBeforeTheFirstHeartbeatIsAnswered()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        core.HeartbeatDelayMs = 1500;
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        // The policy could already be cached in a real deployment; here the heartbeat is slow: requests served meanwhile are not captured.
        for (int i = 0; i < 3; i++) await sut.Client.GetAsync("/health");
        Assert.NotEqual("capturing", sut.Agent!.State);
        await sut.WaitCapturingAsync();
        Assert.Equal(0, await EventCount(core, sut));
        Assert.Equal(0, sut.Agent.Status().ExchangesSeen);
        core.HeartbeatDelayMs = 0;
        await sut.Client.GetAsync("/health");
        Assert.Single(await core.WaitEventsAsync(1));
    }

    [Fact]
    public async Task WithoutAPolicyThereIsNoCapture()
    {
        await using var core = await FakeCore.StartAsync(policy: null);
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitStateAsync("no_policy");
        await sut.Client.GetAsync("/health");
        Assert.Equal(0, await EventCount(core, sut));
        Assert.Equal("no_policy", core.Heartbeats.Last()["state"]!.GetValue<string>());
    }

    [Fact]
    public async Task MissingHmacKeyIsKeyMissing()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core, HmacKey = null });
        await sut.WaitStateAsync("key_missing");
        await sut.Client.GetAsync("/health");
        Assert.Equal(0, await EventCount(core, sut));
        await Wait.UntilAsync(() => core.Heartbeats.Any(h => h["state"]!.GetValue<string>() == "key_missing"), what: "key_missing heartbeat");
    }

    [Theory]
    [InlineData("k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh")]      // 31 bytes
    [InlineData("k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")]    // padding is not allowed
    [InlineData("K1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")]     // kid grammar
    [InlineData("noseparator")]
    public async Task MalformedOrShortKeysAreKeyMissing(string key)
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core, HmacKey = key });
        await sut.WaitStateAsync("key_missing");
    }

    [Fact]
    public async Task KeyWithAnotherKidIsKeyMismatch()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core, HmacKey = "k9:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" });
        await sut.WaitStateAsync("key_mismatch");
    }

    [Fact]
    public async Task AcceptedKidIsUsedDuringARotation()
    {
        var body = PolicyFactory.Shop();
        var hmac = (Dictionary<string, object?>)body["hmac"]!;
        hmac["kid"] = "k2";
        hmac["accept_kids"] = PolicyFactory.List("k1");
        await using var core = await FakeCore.StartAsync(body);
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        await sut.Client.GetAsync("/orders/ORD-9");
        await sut.Agent!.FlushAsync();
        var ev = (await core.WaitEventsAsync(1)).Single();
        Assert.Contains("/orders/{tk1:k1:", ev);
    }

    [Fact]
    public async Task PolicyForAnotherGroupIsRejected()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(group: "payments"));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitStateAsync("policy_rejected");
        await sut.Client.GetAsync("/health");
        Assert.Equal(0, await EventCount(core, sut));
    }

    [Fact]
    public async Task ExpiredPolicyIsRejectedAsExpired()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(notAfter: DateTimeOffset.UtcNow.AddMinutes(-5)));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitStateAsync("expired_policy");
        await sut.Client.GetAsync("/health");
        Assert.Equal(0, await EventCount(core, sut));
    }

    [Fact]
    public async Task PolicySignedByAnUnknownKeyIsRejected()
    {
        await using var core = await FakeCore.StartAsync(policy: null);
        var other = TestEd25519.NewKey();
        core.SetPolicyWith(PolicyFactory.Shop(), other.Seed, PolicyFactory.SigningKid);
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitStateAsync("policy_rejected");
    }

    [Fact]
    public async Task TamperedBodyOrHashIsRejected()
    {
        await using var core = await FakeCore.StartAsync(policy: null);
        var body = PolicyFactory.Shop();
        string env = PolicyFactory.Envelope(body, core.Signer.Seed);
        // Same signature, body of another policy (rate 100% -> 10000 bp is already set; change the epoch).
        var other = PolicyFactory.Shop();
        ((Dictionary<string, object?>)other["hmac"]!)["epoch"] = "2099-01";
        var node = JsonNode.Parse(env)!.AsObject();
        node["body_b64"] = Utf8Util.B64UrlNoPad(PolicyFactory.BodyBytes(other));
        core.PolicyEnvelope = node.ToJsonString();
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitStateAsync("policy_rejected");
    }

    [Fact]
    public async Task ReplayedOlderPolicyIsRefusedAndTheCurrentOneKept()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(issuedSeq: 5));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        string hashBefore = JsonNode.Parse(core.PolicyEnvelope!)!["hash"]!.GetValue<string>();
        var old = PolicyFactory.Shop(issuedSeq: 3);
        ((Dictionary<string, object?>)old["hmac"]!)["epoch"] = "2020-01";
        core.SetPolicy(old);
        int fetches = core.PolicyFetches;
        await Wait.UntilAsync(() => core.PolicyFetches >= fetches + 2, what: "policy polls");
        Assert.Equal("capturing", sut.Agent!.State);
        await Wait.UntilAsync(() => core.Heartbeats.Last()["policy"]!["hash"]!.GetValue<string>() == hashBefore, what: "heartbeat with the kept policy");
    }

    [Fact]
    public async Task MinIssuedSeqFromTheHeartbeatDropsAnOlderPolicy()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(issuedSeq: 2));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        core.MinIssuedSeq = 10;
        await sut.WaitStateAsync("policy_rejected");
        var persisted = JsonNode.Parse(File.ReadAllText(Path.Combine(sut.StateDir, "state.json")))!;
        Assert.Equal(10, persisted["min_issued_seq"]!.GetValue<long>());
        // A fresh policy above the floor is accepted again.
        core.SetPolicy(PolicyFactory.Shop(issuedSeq: 11));
        await sut.WaitCapturingAsync();
    }

    // Usability test 4: tt-core moves min_issued_seq to the new policy in the same heartbeat that
    // announces it; the source switches without an error or a policy_rejected state.
    [Fact]
    public async Task ANormalPolicyChangeReportsNoError()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(issuedSeq: 2));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        int from = core.Heartbeats.Count;
        for (long seq = 3; seq <= 5; seq++)
        {
            long want = seq;
            core.SetPolicy(PolicyFactory.Shop(issuedSeq: seq));
            core.MinIssuedSeq = seq;
            await Wait.UntilAsync(() => core.Heartbeats.Last()["state"]!.GetValue<string>() == "capturing" &&
                core.Heartbeats.Last().TryGetPropertyValue("policy", out var p) && p!["issued_seq"]!.GetValue<long>() == want, what: "policy " + want);
        }
        var hbs = core.Heartbeats.Skip(from).ToList();
        Assert.DoesNotContain(hbs, h => h["state"]!.GetValue<string>() == "policy_rejected");
        var codes = hbs.Last()["last_errors"]!.AsArray().Select(e => e!["code"]!.GetValue<string>()).ToArray();
        Assert.DoesNotContain("policy_below_min_issued_seq", codes);
        Assert.DoesNotContain("policy_rejected", codes);
    }

    [Fact]
    public async Task KillSwitchStopsCaptureDropsQueuesAndSurvivesARestart()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        string dir = Path.Combine(Path.GetTempPath(), "tt-kill-" + Guid.NewGuid().ToString("N"));
        try
        {
            await using (var sut = await Sut.StartAsync(new SutOptions { Core = core, StateDir = dir }))
            {
                await sut.WaitCapturingAsync();
                await sut.Client.GetAsync("/health");
                await sut.Agent!.FlushAsync();
                int before = (await core.WaitEventsAsync(1)).Count;
                core.Kill = true;
                await sut.WaitStateAsync("killed");
                await sut.Client.GetAsync("/health");
                Assert.Equal(before, await EventCount(core, sut));
                Assert.True(JsonNode.Parse(File.ReadAllText(Path.Combine(dir, "state.json")))!["kill"]!.GetValue<bool>());
                // Lifted by a later heartbeat.
                core.Kill = false;
                await sut.WaitCapturingAsync();
            }
            // Killed again, then restarted against a core that no longer answers: the stop is persisted.
            string coreUrl = core.BaseUrl;
            core.Kill = true;
            await using (var sut = await Sut.StartAsync(new SutOptions { Core = core, StateDir = dir }))
            {
                await sut.WaitStateAsync("killed");
            }
            var agent = TrafficTwinAgent.Create(new TrafficTwinOptions
            {
                EnrollUrl = coreUrl,
                EnrollToken = core.Token,
                HmacKey = PolicyFactory.HmacKeyLine,
                ServiceName = "shop-api",
                StateDir = dir,
                RequestTimeout = TimeSpan.FromSeconds(1),
            });
            await core.DisposeAsync();
            await agent.StartAsync();
            Assert.Equal("killed", agent.State);
            await agent.DisposeAsync();
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task RestartWithAnUnreachableCoreDoesNotCaptureUntilAHeartbeatSucceeds()
    {
        var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        string dir = Path.Combine(Path.GetTempPath(), "tt-offline-" + Guid.NewGuid().ToString("N"));
        try
        {
            await using (var sut = await Sut.StartAsync(new SutOptions { Core = core, StateDir = dir }))
            {
                await sut.WaitCapturingAsync();
            }
            string url = core.BaseUrl;
            string token = core.Token;
            await core.DisposeAsync();
            var agent = TrafficTwinAgent.Create(new TrafficTwinOptions
            {
                EnrollUrl = url,
                EnrollToken = token,
                HmacKey = PolicyFactory.HmacKeyLine,
                ServiceName = "shop-api",
                StateDir = dir,
                RequestTimeout = TimeSpan.FromSeconds(1),
            });
            await agent.StartAsync();
            Assert.Equal("starting", agent.State);
            await agent.DisposeAsync();
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task RevokedSourceStopsAndPersistsTheStop()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        Volatile.Write(ref core.RevokeSource, 1);
        await sut.WaitStateAsync("killed");
        Assert.True(JsonNode.Parse(File.ReadAllText(Path.Combine(sut.StateDir, "state.json")))!["revoked"]!.GetValue<bool>());
    }

    [Fact]
    public async Task SamplingOverrideCanOnlyLowerTheRate()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(rateBp: 10000));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        core.SamplingOverrideBp = 0;
        await Wait.UntilAsync(() => core.Heartbeats.Count > 3, what: "heartbeats");
        await Task.Delay(500);
        await sut.Client.GetAsync("/health");
        Assert.Equal(0, await EventCount(core, sut));
        // 20000 bp "raises" nothing: min(override, policy).
        core.SamplingOverrideBp = null;
        await Task.Delay(700);
        await sut.Client.GetAsync("/health");
        await sut.Agent!.FlushAsync();
        Assert.True((await core.WaitEventsAsync(1)).Count >= 1);
    }

    [Fact]
    public async Task RateZeroCapturesNothing()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(rateBp: 0));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        for (int i = 0; i < 10; i++) await sut.Client.GetAsync("/health");
        Assert.Equal(0, await EventCount(core, sut));
        Assert.Equal(10, sut.Agent!.Status().ExchangesSeen);
        Assert.Equal(0, sut.Agent.Status().ExchangesSampled);
    }

    [Fact]
    public async Task NewSigningKeyEndorsedByAPinnedKeyIsAcceptedThenRevoked()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(issuedSeq: 1));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        var k2 = TestEd25519.NewKey();
        string kid2 = "policy-test-2";
        byte[] prefix = Encoding.Latin1.GetBytes("tt-fleet-key/v1\0" + kid2 + "\0");
        byte[] msg = prefix.Concat(k2.Public).ToArray();
        string endorsement = Utf8Util.B64UrlNoPad(TestEd25519.Sign(core.Signer.Seed, msg));
        core.AddSigningKeys = new JsonArray(new JsonObject
        {
            ["kid"] = kid2, ["alg"] = "Ed25519", ["public_key"] = Utf8Util.B64UrlNoPad(k2.Public),
            ["endorsed_by"] = PolicyFactory.SigningKid, ["endorsement"] = endorsement,
        });
        // A key with a bad endorsement must not be added.
        await Wait.UntilAsync(() => File.ReadAllText(Path.Combine(sut.StateDir, "state.json")).Contains(kid2), what: "key persisted");
        // A policy signed with the new key is now accepted.
        var p2 = PolicyFactory.Shop(issuedSeq: 2);
        ((Dictionary<string, object?>)p2["hmac"]!)["epoch"] = "2026-11";
        core.SetPolicyWith(p2, k2.Seed, kid2);
        await Wait.UntilAsync(() => core.Heartbeats.Last().TryGetPropertyValue("policy", out var p) && p!["issued_seq"]!.GetValue<long>() == 2, what: "policy 2 accepted");
        // Revoking it drops the policy signed with it, immediately.
        core.RevokeSigningKeys = new JsonArray(kid2);
        await sut.WaitStateAsync("policy_rejected");
        // A new policy under the original key recovers.
        core.SetPolicy(PolicyFactory.Shop(issuedSeq: 3));
        await sut.WaitCapturingAsync();
    }

    [Fact]
    public async Task ForgedKeyEndorsementIsIgnored()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        var evil = TestEd25519.NewKey();
        var attacker = TestEd25519.NewKey();
        byte[] msg = Encoding.Latin1.GetBytes("tt-fleet-key/v1\0evil\0").Concat(evil.Public).ToArray();
        core.AddSigningKeys = new JsonArray(new JsonObject
        {
            ["kid"] = "evil", ["alg"] = "Ed25519", ["public_key"] = Utf8Util.B64UrlNoPad(evil.Public),
            ["endorsed_by"] = PolicyFactory.SigningKid, ["endorsement"] = Utf8Util.B64UrlNoPad(TestEd25519.Sign(attacker.Seed, msg)),
        });
        int hb = core.Heartbeats.Count;
        await Wait.UntilAsync(() => core.Heartbeats.Count >= hb + 2, what: "heartbeats");
        Assert.DoesNotContain("evil", File.ReadAllText(Path.Combine(sut.StateDir, "state.json")));
    }

    private static JsonObject Endorsed(string kid, byte[] pub, string by, byte[] bySeed)
    {
        byte[] msg = Encoding.Latin1.GetBytes("tt-fleet-key/v1\0" + kid + "\0").Concat(pub).ToArray();
        return new JsonObject
        {
            ["kid"] = kid, ["alg"] = "Ed25519", ["public_key"] = Utf8Util.B64UrlNoPad(pub),
            ["endorsed_by"] = by, ["endorsement"] = Utf8Util.B64UrlNoPad(TestEd25519.Sign(bySeed, msg)),
        };
    }

    private static string[] SigningKids(JsonObject hb) => hb["signing_kids"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray();

    private static string[] KeyErrors(JsonObject hb) =>
        hb["last_errors"]!.AsArray().Select(e => e!["code"]!.GetValue<string>()).Where(c => c.StartsWith("signing_key", StringComparison.Ordinal)).ToArray();

    private static async Task<JsonObject> NextHeartbeatAsync(FakeCore core, int skip = 1)
    {
        int n = core.Heartbeats.Count;
        await Wait.UntilAsync(() => core.Heartbeats.Count >= n + skip + 1, what: "heartbeats");
        return core.Heartbeats.Last();
    }

    [Fact]
    public async Task HeartbeatCarriesTheTrustedSigningKids()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        Assert.Equal(new[] { PolicyFactory.SigningKid }, SigningKids(core.Heartbeats.Last()));
        var k2 = TestEd25519.NewKey();
        var k0 = TestEd25519.NewKey();
        // Added keys show up sorted; a revoked kid disappears and the array stays an array when empty.
        core.AddSigningKeys = new JsonArray(Endorsed("policy-test-2", k2.Public, PolicyFactory.SigningKid, core.Signer.Seed),
            Endorsed("policy-test-0", k0.Public, "policy-test-2", k2.Seed));
        await Wait.UntilAsync(() => SigningKids(core.Heartbeats.Last()).Length == 3, what: "added kids reported");
        Assert.Equal(new[] { "policy-test-0", PolicyFactory.SigningKid, "policy-test-2" }, SigningKids(core.Heartbeats.Last()));
        core.RevokeSigningKeys = new JsonArray(PolicyFactory.SigningKid, "policy-test-0", "policy-test-2");
        await Wait.UntilAsync(() => SigningKids(core.Heartbeats.Last()).Length == 0, what: "revoked kids dropped");
        Assert.Equal(JsonValueKind.Array, JsonDocument.Parse(core.Heartbeats.Last().ToJsonString()).RootElement.GetProperty("signing_kids").ValueKind);
    }

    [Fact]
    public async Task KeyEndorsedByAKidRevokedInTheSameHeartbeatIsNotPinned()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(issuedSeq: 1));
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        var k2 = TestEd25519.NewKey();
        const string kid2 = "policy-test-2";
        lock (core.SigningKeysLock)
        {
            core.AddSigningKeys = new JsonArray(Endorsed(kid2, k2.Public, PolicyFactory.SigningKid, core.Signer.Seed));
            core.RevokeSigningKeys = new JsonArray(PolicyFactory.SigningKid);
        }
        await sut.WaitStateAsync("policy_rejected");
        var hb = await NextHeartbeatAsync(core, 2);
        Assert.Empty(SigningKids(hb));
        var st = JsonNode.Parse(File.ReadAllText(Path.Combine(sut.StateDir, "state.json")))!;
        Assert.DoesNotContain(kid2, st["added_keys"]!.ToJsonString());
        Assert.Contains(PolicyFactory.SigningKid, st["revoked_kids"]!.ToJsonString());
        // A policy signed by the key that was refused is not accepted.
        var p2 = PolicyFactory.Shop(issuedSeq: 2);
        core.SetPolicyWith(p2, k2.Seed, kid2);
        int polls = core.PolicyFetches;
        await Wait.UntilAsync(() => core.PolicyFetches >= polls + 3, what: "policy polls");
        hb = await NextHeartbeatAsync(core);
        Assert.Equal("policy_rejected", sut.Agent!.State);
        Assert.False(hb.ContainsKey("policy"));
    }

    [Fact]
    public async Task EndorsedRotationSurvivesTheRevocationOfTheOldKeyAndARestart()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop(issuedSeq: 1));
        string dir = Path.Combine(Path.GetTempPath(), "tt-rotate-" + Guid.NewGuid().ToString("N"));
        var k2 = TestEd25519.NewKey();
        const string kid2 = "policy-test-2";
        try
        {
            await using (var sut = await Sut.StartAsync(new SutOptions { Core = core, StateDir = dir }))
            {
                await sut.WaitCapturingAsync();
                // tt-core repeats every endorsed key at every heartbeat.
                core.AddSigningKeys = new JsonArray(Endorsed(kid2, k2.Public, PolicyFactory.SigningKid, core.Signer.Seed));
                await Wait.UntilAsync(() => SigningKids(core.Heartbeats.Last()).Contains(kid2), what: "new key pinned");
                // The repeated, already pinned key is neither an error nor a state rewrite.
                DateTime mtime = File.GetLastWriteTimeUtc(Path.Combine(dir, "state.json"));
                var hb = await NextHeartbeatAsync(core, 3);
                Assert.Empty(KeyErrors(hb));
                Assert.Equal(mtime, File.GetLastWriteTimeUtc(Path.Combine(dir, "state.json")));
                // A policy signed by the new key is accepted.
                core.SetPolicyWith(PolicyFactory.Shop(issuedSeq: 2), k2.Seed, kid2);
                await Wait.UntilAsync(() => core.Heartbeats.Last().TryGetPropertyValue("policy", out var p) && p!["issued_seq"]!.GetValue<long>() == 2, what: "policy 2 accepted");
                // Revoking the old key keeps the source capturing under the new one.
                core.RevokeSigningKeys = new JsonArray(PolicyFactory.SigningKid);
                await Wait.UntilAsync(() => SigningKids(core.Heartbeats.Last()).SequenceEqual(new[] { kid2 }), what: "old kid revoked");
                hb = await NextHeartbeatAsync(core, 2);
                Assert.Equal("capturing", sut.Agent!.State);
                Assert.Equal(2, hb["policy"]!["issued_seq"]!.GetValue<long>());
                Assert.Empty(KeyErrors(hb));
            }
            // Restart: the rotated key and the revocation come from the state directory.
            var st = JsonNode.Parse(File.ReadAllText(Path.Combine(dir, "state.json")))!;
            Assert.Contains(kid2, st["added_keys"]!.ToJsonString());
            Assert.Contains(PolicyFactory.SigningKid, st["revoked_kids"]!.ToJsonString());
            await using (var sut = await Sut.StartAsync(new SutOptions { Core = core, StateDir = dir }))
            {
                await sut.WaitCapturingAsync();
                var hb = await NextHeartbeatAsync(core, 2);
                Assert.Equal(new[] { kid2 }, SigningKids(hb));
                Assert.Equal(2, hb["policy"]!["issued_seq"]!.GetValue<long>());
                Assert.Equal("capturing", sut.Agent!.State);
                Assert.Empty(KeyErrors(hb));
            }
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task UnknownEnrollmentTokenFailsWithoutRetryLoopingForever()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        var agent = TrafficTwinAgent.Create(new TrafficTwinOptions
        {
            EnrollUrl = core.BaseUrl,
            EnrollToken = "tte_" + new string('b', 40) + "." + core.Pki.Pin,
            HmacKey = PolicyFactory.HmacKeyLine,
            ServiceName = "shop-api",
            StateDir = Path.Combine(Path.GetTempPath(), "tt-badtoken-" + Guid.NewGuid().ToString("N")),
        });
        await agent.StartAsync();
        Assert.NotEqual("capturing", agent.State);
        Assert.Empty(core.Heartbeats);
        await agent.DisposeAsync();
    }

    [Fact]
    public async Task CertificateIsRenewedWhenTheCoreAsksAndTheNewOneIsUsed()
    {
        await using var core = await FakeCore.StartAsync(PolicyFactory.Shop());
        await using var sut = await Sut.StartAsync(new SutOptions { Core = core });
        await sut.WaitCapturingAsync();
        string before = File.ReadAllText(Path.Combine(sut.StateDir, "enrollment.json"));
        core.AskRenewal = true;
        await Wait.UntilAsync(() => core.Renewals >= 1, what: "renewal");
        core.AskRenewal = false;
        await Wait.UntilAsync(() => File.ReadAllText(Path.Combine(sut.StateDir, "enrollment.json")) != before, what: "enrollment.json updated");
        int hb = core.Heartbeats.Count;
        await Wait.UntilAsync(() => core.Heartbeats.Count >= hb + 2, what: "heartbeats with the renewed certificate");
        Assert.Equal("capturing", sut.Agent!.State);
        await sut.Client.GetAsync("/health");
        await sut.Agent.FlushAsync();
        Assert.NotEmpty(await core.WaitEventsAsync(1));
        if (!OperatingSystem.IsWindows())
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(sut.StateDir, "client.key")));
    }

    [Fact]
    public async Task StaticStartIsIdempotentAndNeverThrows()
    {
        var a = TrafficTwinAgent.Start(new TrafficTwinOptions());   // unconfigured: reports not_configured, does nothing
        var b = TrafficTwinAgent.Start(new TrafficTwinOptions { EnrollUrl = "https://127.0.0.1:1" });
        Assert.Same(a, b);
        Assert.Same(a, TrafficTwinAgent.Current);
        await a.WaitStartedAsync();
        Assert.Equal("starting", a.State);
        await TrafficTwinAgent.StopCurrentAsync();
        Assert.Null(TrafficTwinAgent.Current);
    }

    [Fact]
    public async Task DisabledSdkDoesNothing()
    {
        var agent = TrafficTwinAgent.Create(new TrafficTwinOptions { Disabled = true, EnrollUrl = "https://127.0.0.1:1", ServiceName = "x" });
        await agent.StartAsync();
        Assert.Equal("starting", agent.State);
        await agent.DisposeAsync();
    }

    [Fact]
    public async Task EnvironmentConfiguration()
    {
        var env = new Dictionary<string, string?>
        {
            ["TT_ENROLL_URL"] = "https://tt-core.internal:4318",
            ["TT_ENROLL_TOKEN"] = "tte_x",
            ["TT_HMAC_KEY_FILE"] = "/run/secrets/k",
            ["OTEL_SERVICE_NAME"] = "Shop API_v2",
            ["TT_ENROLL_CSR"] = "0",
            ["TT_DEBUG"] = "1",
            ["TT_HEARTBEAT_INTERVAL_MS"] = "50",
        };
        var o = TrafficTwinOptions.FromEnvironment(n => env.GetValueOrDefault(n));
        Assert.Equal("shop-api_v2", o.ServiceName);
        Assert.False(o.UseCsr);
        Assert.True(o.Debug);
        Assert.Equal(TimeSpan.FromMilliseconds(100), o.HeartbeatInterval);
        Assert.Equal("/run/secrets/k", o.HmacKeyFile);
        env["TT_SERVICE_NAME"] = "ORDERS";
        Assert.Equal("orders", TrafficTwinOptions.FromEnvironment(n => env.GetValueOrDefault(n)).ServiceName);
        env["TT_SERVICE_NAME"] = "!!!";
        Assert.Null(TrafficTwinOptions.FromEnvironment(n => env.GetValueOrDefault(n)).ServiceName);
        await Task.CompletedTask;
    }
}
