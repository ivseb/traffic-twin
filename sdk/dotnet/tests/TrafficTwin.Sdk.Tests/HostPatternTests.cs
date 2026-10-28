using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using TrafficTwin.Sdk.Sanitizing;
using TrafficTwin.Sdk.Tests.Helpers;
using Xunit;

namespace TrafficTwin.Sdk.Tests;

/// <summary>Host autodiscovery (spec v1.5): the examples of sanitizer.md 3.5, the IPv6 parser, the class table and strict mode.</summary>
public class HostPatternTests
{
    private static Dictionary<string, object?> EmptyBody(string? discovery)
    {
        string root = Paths.Conformance();
        var raw = (Dictionary<string, object?>)Plain.From(JsonParser.Parse(File.ReadAllBytes(Path.Combine(root, "policies", "empty.json"))), true)!;
        if (discovery != null) raw["hosts"] = new Dictionary<string, object?> { ["discovery"] = discovery };
        return raw;
    }

    private static Sanitizer Make(string? discovery)
    {
        var policy = new Policy(PolicyChecks.ValidateBodySchema(EmptyBody(discovery)));
        var ring = PolicyChecks.ParseKeyRing(PolicyFactory.HmacKeyLine);
        var (kid, key) = PolicyChecks.SelectKey(ring, policy);
        return new Sanitizer(policy, kid, key);
    }

    private static string Service(Sanitizer s, string urlBase)
    {
        var ex = new Exchange { Inbound = false, Method = "GET", RawPath = Encoding.UTF8.GetBytes("/x"), UrlBase = urlBase, Status = 200 };
        var r = s.Run(ex, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        Assert.Equal(Outcome.Event, r.Outcome);
        var m = Regex.Match(r.Canonical!, "\"service\":\"([^\"]*)\"");
        Assert.True(m.Success, r.Canonical);
        return m.Groups[1].Value;
    }

    [Fact]
    public void ExamplesOfSection35()
    {
        var s = Make(null);
        var cases = new (string, string)[]
        {
            ("https://api.carrier.example", "host:api.carrier.example"),
            ("HTTPS://API.Carrier.example:443", "host:api.carrier.example"),
            ("https://api.carrier.example.:8443", "host:api.carrier.example:8443"),
            ("https://t-3912345678.tenant.example", "host:{*}.tenant.example"),
            ("https://cdn-9f8e7d6c5b4a.assets.example", "host:{*}.assets.example"),
            ("https://1password.example", "host:{*}.example"),
            ("https://xn--bcher-kva.example", "host:xn--bcher-kva.example"),
            ("http://10.0.0.5:8080", "host:ip:private:8080"),
            ("https://[2606:4700::1111]", "host:ip:public"),
            ("https://api..carrier.example", "host:invalid"),
            ("https://ab12cd34ef56.0012345678.cdn.example", "host:{*}.{*}.cdn.example"),
            ("https://bücher.example", "host:invalid"),
            ("https://[fe80::1%25eth0]", "host:invalid"),
            ("https://[::1", "host:invalid"),
            ("https://[::1]x", "host:invalid"),
            ("https://010.0.0.1", "host:{*}.{*}.{*}.{*}"),
            ("https://2130706433", "host:{*}"),
        };
        foreach (var (url, want) in cases) Assert.True(want == Service(s, url), url);
    }

    [Fact]
    public void StrictModeKeepsUnlistedAndDiscoveryModeIsStillAPattern()
    {
        var strict = Make("off");
        Assert.Equal("host:unlisted", Service(strict, "https://api.carrier.example"));
        Assert.Equal("host:unlisted", Service(strict, "http://10.0.0.5:8080"));
        Assert.Equal("host:unlisted", Service(strict, "https://api..carrier.example"));
        Assert.Equal("host:invalid", Service(strict, "https://[::1"));
        Assert.Equal("host:unlisted", Service(strict, "https://[2606:4700::1111]"));
        Assert.Equal("host:api.carrier.example", Service(Make("auto"), "https://api.carrier.example"));
    }

    [Fact]
    public void PolicyHostsObjectIsValidated()
    {
        foreach (object? bad in new object?[] { "on", "", 1L, true, null })
        {
            var b = EmptyBody(null);
            b["hosts"] = new Dictionary<string, object?> { ["discovery"] = bad };
            Assert.Throws<RefusedException>(() => PolicyChecks.ValidateBodySchema(b));
        }
        var empty = EmptyBody(null);
        empty["hosts"] = new Dictionary<string, object?>();
        Assert.Throws<RefusedException>(() => PolicyChecks.ValidateBodySchema(empty));
        var extra = EmptyBody(null);
        extra["hosts"] = new Dictionary<string, object?> { ["discovery"] = "off", ["extra"] = "x" };
        Assert.Throws<RefusedException>(() => PolicyChecks.ValidateBodySchema(extra));
        var str = EmptyBody(null);
        str["hosts"] = "off";
        Assert.Throws<RefusedException>(() => PolicyChecks.ValidateBodySchema(str));
    }

    [Fact]
    public void Ipv6ParserFollowsTheSpecTextForm()
    {
        foreach (string ok in new[] { "::", "::1", "1::", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8", "::ffff:1.2.3.4", "64:ff9b::10.0.0.1", "1:2:3:4:5:6:1.2.3.4", "2001:db8::", "abcd::" })
            Assert.NotNull(HostPattern.ParseIpv6(ok));
        foreach (string bad in new[]
        {
            "", ":", ":::", "1::2::3", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7::8", "12345::", "g::", "::1%eth0", "::01.2.3.4", "::1.2.3",
            "::1.2.3.256", "1.2.3.4::", "::1.2.3.4:1", "1:2:3:4:5:6:7:1.2.3.4", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", "::ffff:1.2.3.4.5", "[::1]",
        })
            Assert.Null(HostPattern.ParseIpv6(bad));
    }

    [Fact]
    public void ClassTableIsClosedAndEmbeddedIpv4IsLookedUpFirst()
    {
        var s = Make(null);
        var cases = new (string, string)[]
        {
            ("http://0.1.2.3", "private"), ("http://100.64.0.1", "private"), ("http://100.128.0.1", "public"), ("http://172.15.0.1", "public"),
            ("http://172.31.255.255", "private"), ("http://198.19.255.255", "private"), ("http://198.20.0.0", "public"),
            ("http://169.254.169.254", "private"), ("http://8.8.8.8", "public"), ("http://[::ffff:8.8.8.8]", "public"),
            ("http://[::ffff:10.0.0.1]", "private"), ("http://[64:ff9b::808:808]", "public"), ("http://[64:ff9b::a00:1]", "private"),
            ("http://[64:ff9b:1::1]", "private"), ("http://[::8.8.8.8]", "private"), ("http://[100::1]", "private"), ("http://[100:0:0:1::1]", "public"),
            ("http://[2001:1::1]", "private"), ("http://[2001:200::1]", "public"), ("http://[2001:db8::1]", "private"), ("http://[fd00::1]", "private"),
            ("http://[fbff::1]", "public"), ("http://[febf::1]", "private"), ("http://[fec0::1]", "private"), ("http://[ff02::1]", "private"),
            ("http://[2606:4700::1111]", "public"),
        };
        foreach (var (url, cls) in cases) Assert.True("host:ip:" + cls == Service(s, url), url);
        Assert.Equal("host:ip:private:8080", Service(s, "http://[::1]:8080"));
        Assert.Equal("host:ip:private", Service(s, "http://[::1]:80"));
    }

    [Fact]
    public void TheHostIsPassedAsTheClientSeesIt()
    {
        // Spec v1.5 point 9: brackets for IPv6, final dot kept, no IDN conversion; the sanitizer decides.
        Assert.Equal("http://[::1]:8080", Capture.CaptureUtil.UrlBase(new Uri("http://[::1]:8080/x")));
        Assert.Equal("http://[::1]", Capture.CaptureUtil.UrlBase(new Uri("http://[::1]/x")));
        Assert.Equal("https://api.carrier.example.", Capture.CaptureUtil.UrlBase(new Uri("https://api.carrier.example./x")));
        Assert.Equal("https://xn--bcher-kva.example", Capture.CaptureUtil.UrlBase(new Uri("https://xn--bcher-kva.example/x")));
        Assert.Equal("host:invalid", Service(Make(null), Capture.CaptureUtil.UrlBase(new Uri("https://bücher.example/x"))));
    }
}
