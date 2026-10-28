using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using TrafficTwin.Sdk.Capture;
using TrafficTwin.Sdk.Sanitizing;
using TrafficTwin.Sdk.Tests.Helpers;
using Xunit;

namespace TrafficTwin.Sdk.Tests;

public class BodyDecoderTests
{
    private static byte[] Gzip(byte[] data, CompressionLevel level = CompressionLevel.Optimal)
    {
        var ms = new MemoryStream();
        using (var z = new GZipStream(ms, level, true)) z.Write(data);
        return ms.ToArray();
    }

    private static byte[] Zlib(byte[] data, CompressionLevel level = CompressionLevel.Optimal)
    {
        var ms = new MemoryStream();
        using (var z = new ZLibStream(ms, level, true)) z.Write(data);
        return ms.ToArray();
    }

    private static byte[] Sample(int n, int seed, bool compressible)
    {
        var r = new Random(seed);
        var b = new byte[n];
        if (compressible) for (int i = 0; i < n; i++) b[i] = (byte)("{\"a\":\"hello world\"}"[i % 19]);
        else r.NextBytes(b);
        return b;
    }

    public static IEnumerable<object[]> Sizes() => new[] { 0, 1, 2, 100, 5000, 70000, 1_000_000 }.SelectMany(n => new[] { true, false }.Select(c => new object[] { n, c }));

    [Theory]
    [MemberData(nameof(Sizes))]
    public void GzipAndZlibRoundTrip(int n, bool compressible)
    {
        if (n == 0)
        {
            // Some runtimes write nothing for an empty stream: use hand-made empty streams (stored block / empty fixed block).
            byte[] emptyGzip = { 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] emptyZlib = { 0x78, 0x9c, 3, 0, 0, 0, 0, 1 };
            Assert.Empty(BodyDecoder.Decode(emptyGzip, false, 100).Data!);
            Assert.Empty(BodyDecoder.Decode(emptyZlib, true, 100).Data!);
            return;
        }
        byte[] data = Sample(n, n, compressible);
        foreach (var level in new[] { CompressionLevel.Optimal, CompressionLevel.Fastest, CompressionLevel.NoCompression, CompressionLevel.SmallestSize })
        {
            var g = BodyDecoder.Decode(Gzip(data, level), false, 10_000_000);
            Assert.Equal(BodyDecoder.Status.Ok, g.Status);
            Assert.True(data.AsSpan().SequenceEqual(g.Data));
            var z = BodyDecoder.Decode(Zlib(data, level), true, 10_000_000);
            Assert.Equal(BodyDecoder.Status.Ok, z.Status);
            Assert.True(data.AsSpan().SequenceEqual(z.Data));
        }
    }

    [Fact]
    public void TruncatedStreamsAreErrors()
    {
        byte[] data = Sample(3000, 1, true);
        foreach (bool zl in new[] { false, true })
        {
            byte[] c = zl ? Zlib(data) : Gzip(data);
            foreach (int cut in new[] { 1, 2, 4, 6, 8, 12, c.Length / 2, c.Length - 1, 3 })
            {
                var r = BodyDecoder.Decode(c.AsSpan(0, c.Length - cut).ToArray(), zl, 10_000_000);
                Assert.True(r.Status == BodyDecoder.Status.Error, $"zlib={zl} cut={cut}");
            }
            Assert.Equal(BodyDecoder.Status.Error, BodyDecoder.Decode(Array.Empty<byte>(), zl, 1000).Status);
        }
    }

    [Fact]
    public void BytesAfterTheEndAndMultiMemberStreamsAreErrors()
    {
        byte[] data = Sample(500, 2, true);
        Assert.Equal(BodyDecoder.Status.Error, BodyDecoder.Decode(Gzip(data).Concat(new byte[] { 1, 2, 3 }).ToArray(), false, 10_000).Status);
        Assert.Equal(BodyDecoder.Status.Error, BodyDecoder.Decode(Gzip(data).Concat(Gzip(data)).ToArray(), false, 10_000).Status);
        Assert.Equal(BodyDecoder.Status.Error, BodyDecoder.Decode(Zlib(data).Concat(new byte[] { 0 }).ToArray(), true, 10_000).Status);
    }

    [Fact]
    public void CorruptChecksumsAndHeadersAreErrors()
    {
        byte[] data = Sample(500, 3, true);
        byte[] g = Gzip(data);
        var bad = (byte[])g.Clone();
        bad[bad.Length - 5] ^= 0xff; // crc
        Assert.Equal(BodyDecoder.Status.Error, BodyDecoder.Decode(bad, false, 10_000).Status);
        bad = (byte[])g.Clone();
        bad[bad.Length - 1] ^= 0xff; // isize
        Assert.Equal(BodyDecoder.Status.Error, BodyDecoder.Decode(bad, false, 10_000).Status);
        bad = (byte[])g.Clone();
        bad[0] = 0;
        Assert.Equal(BodyDecoder.Status.Error, BodyDecoder.Decode(bad, false, 10_000).Status);
        bad = (byte[])g.Clone();
        bad[3] |= 0x80; // reserved flag
        Assert.Equal(BodyDecoder.Status.Error, BodyDecoder.Decode(bad, false, 10_000).Status);
        byte[] z = Zlib(data);
        bad = (byte[])z.Clone();
        bad[bad.Length - 1] ^= 1;
        Assert.Equal(BodyDecoder.Status.Error, BodyDecoder.Decode(bad, true, 10_000).Status);
        bad = (byte[])z.Clone();
        bad[1] ^= 1; // header check bits
        Assert.Equal(BodyDecoder.Status.Error, BodyDecoder.Decode(bad, true, 10_000).Status);
        // A raw deflate stream (no zlib header) is not "deflate" for 9.0.
        var raw = new MemoryStream();
        using (var d = new DeflateStream(raw, CompressionLevel.Optimal, true)) d.Write(data);
        Assert.Equal(BodyDecoder.Status.Error, BodyDecoder.Decode(raw.ToArray(), true, 10_000).Status);
    }

    [Fact]
    public void RandomGarbageNeverCrashesAndNeverDecodes()
    {
        var r = new Random(99);
        for (int i = 0; i < 2000; i++)
        {
            var b = new byte[r.Next(0, 200)];
            r.NextBytes(b);
            if (i % 2 == 0 && b.Length > 2) { b[0] = 0x1f; b[1] = 0x8b; b[2] = 8; }
            if (i % 5 == 1 && b.Length > 2) { b[0] = 0x78; b[1] = 0x9c; }
            var g = BodyDecoder.Decode(b, false, 1000);
            var z = BodyDecoder.Decode(b, true, 1000);
            Assert.NotEqual(BodyDecoder.Status.Ok, g.Status);
            Assert.NotEqual(BodyDecoder.Status.Ok, z.Status);
        }
    }

    [Fact]
    public void DecompressionBombStopsAtTheCap()
    {
        byte[] zeros = new byte[200_000_000];
        byte[] g = Gzip(zeros, CompressionLevel.SmallestSize);
        Assert.True(g.Length < 400_000);
        var sw = Stopwatch.StartNew();
        var r = BodyDecoder.Decode(g, false, 1_048_577);
        sw.Stop();
        Assert.Equal(BodyDecoder.Status.Cap, r.Status);
        Assert.True(sw.ElapsedMilliseconds < 3000, "took " + sw.ElapsedMilliseconds + " ms");
        // Exactly below the cap decodes; at the cap it is "cap" (output >= cap).
        byte[] exact = Sample(1000, 4, true);
        Assert.Equal(BodyDecoder.Status.Ok, BodyDecoder.Decode(Gzip(exact), false, 1001).Status);
        Assert.Equal(BodyDecoder.Status.Cap, BodyDecoder.Decode(Gzip(exact), false, 1000).Status);
    }
}

public class JsonTests
{
    [Theory]
    [InlineData("184", "184")]
    [InlineData("73.40", "73.4")]
    [InlineData("1.50", "1.5")]
    [InlineData("15e-1", "1.5")]
    [InlineData("-0.0", "0")]
    [InlineData("-0", "0")]
    [InlineData("1E3", "1000")]
    [InlineData("0.0015", "0.0015")]
    [InlineData("1000000", "1000000")]
    [InlineData("1e21", "1e+21")]
    [InlineData("1e20", "100000000000000000000")]
    [InlineData("1e-6", "0.000001")]
    [InlineData("1e-7", "1e-7")]
    [InlineData("1.5e-7", "1.5e-7")]
    [InlineData("123456789012345678901234567890", "1.2345678901234567890123456789e+29")]
    [InlineData("0.000", "0")]
    [InlineData("-12.5E+2", "-1250")]
    [InlineData("100", "100")]
    [InlineData("1e0", "1")]
    public void CanonicalNumbers(string lex, string expected) => Assert.Equal(expected, JsonNumbers.Canonical(lex));

    [Theory]
    [InlineData("1", true)]
    [InlineData("1e9999", true)]
    [InlineData("1e10000", false)]
    [InlineData("1e+09999", true)]
    [InlineData("1E-10000", false)]
    public void LexemeLimits(string lex, bool ok) => Assert.Equal(ok, JsonNumbers.WithinLimits(lex));

    [Fact]
    public void LexemeLimitOf64Bytes()
    {
        Assert.True(JsonNumbers.WithinLimits(new string('1', 64)));
        Assert.False(JsonNumbers.WithinLimits(new string('1', 65)));
    }

    private static bool Valid(string s) => Valid(Encoding.UTF8.GetBytes(s));

    private static bool Valid(byte[] b)
    {
        try { JsonParser.Parse(b); return true; }
        catch (JsonException2) { return false; }
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("0")]
    [InlineData("-1.5e+3")]
    [InlineData("\"x\"")]
    [InlineData("true")]
    [InlineData(" \t\r\n[1, 2 ,3] \n")]
    [InlineData("{\"a\":{\"b\":[null,false,\"\\u00e8\\ud83d\\ude00\"]}}")]
    public void AcceptsRfc8259(string doc) => Assert.True(Valid(doc));

    [Theory]
    [InlineData("")]
    [InlineData("[1,]")]
    [InlineData("{\"a\":1,}")]
    [InlineData("[1 2]")]
    [InlineData("{'a':1}")]
    [InlineData("// c\n{}")]
    [InlineData("{} {}")]
    [InlineData("NaN")]
    [InlineData("[Infinity]")]
    [InlineData("01")]
    [InlineData("1.")]
    [InlineData(".5")]
    [InlineData("+1")]
    [InlineData("1e")]
    [InlineData("\"a\nb\"")]
    [InlineData("\"\\x41\"")]
    [InlineData("\"\\u12\"")]
    [InlineData("\"abc")]
    [InlineData("tru")]
    [InlineData("{\"a\" 1}")]
    [InlineData("{1:2}")]
    [InlineData("\u000b[]")]
    public void RejectsEverythingElse(string doc) => Assert.False(Valid(doc));

    [Fact]
    public void RejectsBomAndInvalidUtf8()
    {
        Assert.False(Valid(new byte[] { 0xef, 0xbb, 0xbf, (byte)'{', (byte)'}' }));
        Assert.False(Valid(new byte[] { (byte)'"', 0xc0, 0xaf, (byte)'"' }));        // overlong
        Assert.False(Valid(new byte[] { (byte)'"', 0xed, 0xa0, 0x80, (byte)'"' }));  // encoded surrogate
        Assert.False(Valid(new byte[] { (byte)'"', 0xf4, 0x90, 0x80, 0x80, (byte)'"' })); // > U+10FFFF
        Assert.False(Valid(new byte[] { (byte)'"', 0xff, (byte)'"' }));
        Assert.False(Valid(new byte[] { (byte)'"', 0xe2, 0x82, (byte)'"' }));         // truncated
        Assert.True(Valid(new byte[] { (byte)'"', 0xf0, 0x9f, 0x98, 0x80, (byte)'"' }));
        // Invalid UTF-8 inside a KEY is invalid too.
        Assert.False(Valid(new byte[] { (byte)'{', (byte)'"', 0xff, (byte)'"', (byte)':', (byte)'1', (byte)'}' }));
    }

    [Fact]
    public void LoneSurrogateEscapesAreFlaggedNotRejected()
    {
        var n = (JStr)JsonParser.Parse(Encoding.UTF8.GetBytes("\"\\ud800\""));
        Assert.True(n.Bad);
        Assert.False(((JStr)JsonParser.Parse(Encoding.UTF8.GetBytes("\"\\ud83d\\ude00\""))).Bad);
        Assert.True(((JStr)JsonParser.Parse(Encoding.UTF8.GetBytes("\"\\ude00\\ud83d\""))).Bad);
        var o = (JObj)JsonParser.Parse(Encoding.UTF8.GetBytes("{\"\\udc00\":1}"));
        Assert.True(o.Members[0].Key.Bad);
    }

    [Fact]
    public void NumbersKeepTheirLexeme()
    {
        var a = (JArr)JsonParser.Parse(Encoding.UTF8.GetBytes("[1.50,1E3,-0,123456789012345678901234567890,0.1e-400]"));
        Assert.Equal(new[] { "1.50", "1E3", "-0", "123456789012345678901234567890", "0.1e-400" }, a.Items.Select(x => ((JNum)x).Lex));
    }

    [Fact]
    public void DeepNestingIsParsedIteratively()
    {
        string deep = new string('[', 200_000) + new string(']', 200_000);
        Assert.True(Valid(deep));
        Assert.False(Valid(new string('[', 200_000) + new string(']', 199_999)));
        string deepObj = string.Concat(Enumerable.Repeat("{\"a\":", 100_000)) + "1" + new string('}', 100_000);
        Assert.True(Valid(deepObj));
    }

    [Fact]
    public void WriterEscapesAsTtCjson()
    {
        Assert.Equal("\"a\\\"b\\\\c/\\u0000\\u001f\\u007f\\u00e8\\ud83d\\ude00\"", Canonical.WriteString("a\"b\\c/\0\u001f\u007f\u00e8\U0001F600"));
        var m = new Dictionary<string, object?> { ["b"] = new CNum("1"), ["a"] = new List<object?> { true, false, null, "x" }, ["\U0001F600"] = "s", ["\uffff"] = "t" };
        // Keys sort by UTF-8 bytes: U+FFFF (EF BF BF) before U+1F600 (F0 9F 98 80).
        Assert.Equal("{\"a\":[true,false,null,\"x\"],\"b\":1,\"\\uffff\":\"t\",\"\\ud83d\\ude00\":\"s\"}", Canonical.Write(m));
    }

    [Fact]
    public void Utf8CompareFollowsByteOrder()
    {
        Assert.True(Utf8Util.CmpUtf8("\uffff", "\U0001F600") < 0);
        Assert.True(Utf8Util.CmpUtf8("a", "b") < 0);
        Assert.True(Utf8Util.CmpUtf8("ab", "a") > 0);
        Assert.Equal(0, Utf8Util.CmpUtf8("é", "é"));
    }
}

public class TapAndStreamTests
{
    [Fact]
    public void TapKeepsThePrefixAndCountsTheRest()
    {
        var t = new BodyTap(10);
        t.Add(Encoding.ASCII.GetBytes("0123456"));
        t.Add(Encoding.ASCII.GetBytes("789abcdef"));
        t.Add(ReadOnlySpan<byte>.Empty);
        Assert.Equal(16, t.Total);
        Assert.Equal("0123456789", Encoding.ASCII.GetString(t.Bytes()));
        t.Reset();
        Assert.Equal(0, t.Total);
        Assert.Empty(t.Bytes());
    }

    [Fact]
    public async Task ReadTeeForwardsEverythingUnchanged()
    {
        byte[] data = new byte[100_000];
        new Random(5).NextBytes(data);
        var tap = new BodyTap(1 << 20);
        bool? done = null;
        await using (var tee = new TeeReadStream(new MemoryStream(data), tap, e => done = e))
        {
            var buf = new byte[777];
            var all = new MemoryStream();
            int n;
            while ((n = await tee.ReadAsync(buf, 0, buf.Length)) > 0) all.Write(buf, 0, n);
            Assert.True(data.AsSpan().SequenceEqual(all.ToArray()));
        }
        Assert.True(done);
        Assert.True(tap.Ended);
        Assert.Equal(data.Length, tap.Total);
        Assert.True(data.AsSpan().SequenceEqual(tap.Bytes()));
    }

    [Fact]
    public void ReadTeeDisposedEarlyIsNotEnded()
    {
        var tap = new BodyTap(100);
        bool? done = null;
        var tee = new TeeReadStream(new MemoryStream(new byte[50]), tap, e => done = e);
        tee.ReadByte();
        tee.Dispose();
        Assert.False(done);
        Assert.False(tap.Ended);
        Assert.Equal(1, tap.Total);
    }

    [Fact]
    public async Task WriteTeeWritesFirstThenCountsAndDoesNotCloseTheInner()
    {
        var inner = new MemoryStream();
        var tap = new BodyTap(5);
        var tee = new TeeWriteStream(inner, tap);
        await tee.WriteAsync(Encoding.ASCII.GetBytes("abc"));
        tee.Write(Encoding.ASCII.GetBytes("defgh"), 0, 5);
        tee.WriteByte((byte)'i');
        await tee.FlushAsync();
        await tee.DisposeAsync();
        Assert.Equal("abcdefghi", Encoding.ASCII.GetString(inner.ToArray()));
        Assert.True(inner.CanWrite);
        Assert.Equal(9, tap.Total);
        Assert.Equal("abcde", Encoding.ASCII.GetString(tap.Bytes()));
    }
}

public class FrameworkRouteTests
{
    private static string? N(string route, string fw)
    {
        var r = Sanitizer.NormalizeFrameworkRoute(route, fw);
        return r == null ? null : "/" + string.Join("/", r.Select(s => s.Lit ?? "{" + s.Param + "}"));
    }

    [Theory]
    [InlineData("/orders/{id}", "/orders/{id}")]
    [InlineData("/orders/{id:int}", "/orders/{id}")]
    [InlineData("/orders/{id:int:min(1)}", "/orders/{id}")]
    [InlineData("orders/{id:guid}/lines", "/orders/{id}/lines")]
    [InlineData("/orders/{id?}", null)]
    [InlineData("/orders/{id=5}", null)]
    [InlineData("/files/{*path}", null)]
    [InlineData("/files/{**path}", null)]
    [InlineData("/orders/{id:int?}", null)]
    [InlineData("/{controller}/{action}", "/{controller}/{action}")]
    [InlineData("/a-{x}", null)]
    [InlineData("/", "/")]
    public void AspNetCore(string route, string? expected) => Assert.Equal(expected, N(route, "aspnetcore"));

    [Theory]
    [InlineData("express", "/api/orders/:id(\\\\d+)", "/api/orders/{id}")]
    [InlineData("express", "/api/orders/:id(\\d+)", "/api/orders/{id}")]
    [InlineData("express", "/api/orders/:id", "/api/orders/{id}")]
    [InlineData("express", "/orders/:id?", null)]
    [InlineData("express", "/orders/:a-:b", null)]
    [InlineData("express", "/orders/*", null)]
    [InlineData("gin", "/files/*path", null)]
    [InlineData("gin", "/users/:id", "/users/{id}")]
    [InlineData("flask", "/u/<id>", "/u/{id}")]
    [InlineData("flask", "/u/<int:id>", "/u/{id}")]
    [InlineData("flask", "/u/<path:p>", null)]
    [InlineData("django", "/u/<slug:s>", "/u/{s}")]
    [InlineData("fastapi", "/u/{id}", "/u/{id}")]
    [InlineData("fastapi", "/u/{id:int}", "/u/{id}")]
    [InlineData("fastapi", "/u/{id:path}", null)]
    [InlineData("spring", "/u/{id:[0-9]+}", "/u/{id}")]
    [InlineData("spring", "/u/**", null)]
    [InlineData("spring", "/u/{*rest}", null)]
    [InlineData("jaxrs", "/u/{ id : [0-9]+ }", "/u/{id}")]
    [InlineData("jaxrs", "/u/{id}", "/u/{id}")]
    [InlineData("chi", "/u/{id:[0-9]+}", "/u/{id}")]
    [InlineData("chi", "/u/*", null)]
    [InlineData("nethttp", "/u/{id}/{$}", "/u/{id}")]
    [InlineData("nethttp", "/u/{rest...}", null)]
    [InlineData("laravel", "/u/{id}", "/u/{id}")]
    [InlineData("laravel", "/u/{id?}", null)]
    [InlineData("symfony", "/u/{id<\\d+>}", "/u/{id}")]
    [InlineData("symfony", "/u/{id?}", null)]
    [InlineData("symfony", "/u/{id?7}", null)]
    [InlineData("unknown", "/u/{id}", null)]
    public void OtherFrameworks(string fw, string route, string? expected) => Assert.Equal(expected, N(route, fw));
}

public class PolicyChecksTests
{
    private static readonly (byte[] Seed, byte[] Public) Key = TestEd25519.NewKey();
    private static IReadOnlyDictionary<string, byte[]> Keys => new Dictionary<string, byte[]> { [PolicyFactory.SigningKid] = Key.Public };

    private static Dictionary<string, object?> Env(Dictionary<string, object?>? body = null) =>
        (Dictionary<string, object?>)Plain.From(JsonParser.Parse(Encoding.UTF8.GetBytes(PolicyFactory.Envelope(body ?? PolicyFactory.Shop(), Key.Seed))), true)!;

    private static void Rejected(Dictionary<string, object?> env, string? why = null)
    {
        var ex = Assert.Throws<RefusedException>(() => PolicyChecks.VerifyEnvelope(env, Keys, true));
        Assert.Equal("policy_rejected", ex.Code);
        if (why != null) Assert.Contains(why, ex.Detail);
    }

    [Fact]
    public void AValidEnvelopeVerifies()
    {
        var v = PolicyChecks.VerifyEnvelope(Env(), Keys, true);
        Assert.StartsWith("sha256:", v.Hash);
        Assert.Equal("p-shop", v.Body["policy_id"]);
    }

    [Fact]
    public void EveryTamperingIsRejected()
    {
        var e = Env(); e["extra"] = "x"; Rejected(e, "envelope field");
        e = Env(); e["format"] = "tt.policy.compiled/v2"; Rejected(e, "envelope format");
        e = Env(); ((Dictionary<string, object?>)e["signature"]!)["alg"] = "RS256"; Rejected(e, "signature");
        e = Env(); ((Dictionary<string, object?>)e["signature"]!)["kid"] = "other"; Rejected(e, "unknown kid");
        e = Env(); e["hash"] = "sha256:" + new string('0', 64); Rejected(e, "hash");
        e = Env(); e["hash"] = ((string)e["hash"]!).ToUpperInvariant(); Rejected(e, "hash");
        e = Env(); e["body_b64"] = ((string)e["body_b64"]!) + "="; Rejected(e, "body_b64");
        e = Env(); e["body_b64"] = ((string)e["body_b64"]!).Replace('-', '+').Replace('_', '/') + "!"; Rejected(e);
        e = Env(); ((Dictionary<string, object?>)e["signature"]!)["sig"] = "AAAA"; Rejected(e, "signature encoding");
        e = Env(); var sig = (string)((Dictionary<string, object?>)e["signature"]!)["sig"]!;
        ((Dictionary<string, object?>)e["signature"]!)["sig"] = (sig[0] == 'A' ? 'B' : 'A') + sig.Substring(1); Rejected(e, "signature");
        e = Env(); e["version"] = new Lex("2"); Rejected(e, "version mismatch");
        e = Env(); e["policy_id"] = "p-other"; Rejected(e, "policy_id mismatch");
        e = Env(); e["issued_seq"] = new Lex("9"); Rejected(e, "issued_seq mismatch");
        e = Env(); e.Remove("issued_seq"); Rejected(e, "issued_seq mismatch");
    }

    [Fact]
    public void BodiesThatBreakTheSchemaAreRejectedEvenWhenSigned()
    {
        void Bad(Action<Dictionary<string, object?>> mutate, string why)
        {
            var b = PolicyFactory.Shop();
            mutate(b);
            Rejected(Env(b), why);
        }
        Bad(b => b["unexpected"] = PolicyFactory.N(1), "unexpected");
        Bad(b => ((Dictionary<string, object?>)b["hmac"]!)["kid"] = "K1", "hmac.kid");
        Bad(b => ((Dictionary<string, object?>)b["hmac"]!)["accept_kids"] = PolicyFactory.List("a", "b", "c", "d", "e"), "accept_kids");
        Bad(b => ((Dictionary<string, object?>)b["sampling"]!)["rate_bp"] = PolicyFactory.N(10001), "rate_bp");
        Bad(b => ((Dictionary<string, object?>)b["sampling"]!)["trust_baggage"] = "yes", "trust_baggage");
        Bad(b => ((Dictionary<string, object?>)b["limits"]!)["max_depth"] = PolicyFactory.N(0), "max_depth");
        Bad(b => b["not_after"] = "tomorrow", "not_after");
        Bad(b => b["version"] = PolicyFactory.N(0), "version");
        Bad(b => ((Dictionary<string, object?>)b["segments"]!)["auto_words"] = true, "auto_words_expires_at");
        Bad(b => ((Dictionary<string, object?>)b["targets"]!)["groups"] = PolicyFactory.List(), "groups");
        Bad(b => ((Dictionary<string, object?>)((Dictionary<string, object?>)b["global"]!)["request"]!)["headers"] = PolicyFactory.Map(("Content-Type", PolicyFactory.Keep())), "name");
        Bad(b => ((Dictionary<string, object?>)((Dictionary<string, object?>)b["global"]!)["request"]!)["body"] = PolicyFactory.List(PolicyFactory.Rule("$[0]", PolicyFactory.Keep())), "path");
        Bad(b => ((Dictionary<string, object?>)((Dictionary<string, object?>)b["global"]!)["request"]!)["headers"] = PolicyFactory.Map(("x-a", PolicyFactory.Hmac("subject"))), "reserved");
        Bad(b => ((Dictionary<string, object?>)((Dictionary<string, object?>)b["global"]!)["request"]!)["headers"] = PolicyFactory.Map(("x-a", PolicyFactory.Hmac("Bad Domain"))), "string");
        Bad(b => ((Dictionary<string, object?>)((Dictionary<string, object?>)b["global"]!)["request"]!)["headers"] = PolicyFactory.Map(("x-a", PolicyFactory.BucketNum(5, 5))), "increasing");
        Bad(b => ((Dictionary<string, object?>)((Dictionary<string, object?>)b["global"]!)["request"]!)["headers"] = PolicyFactory.Map(("x-a", PolicyFactory.Map(("action", "burn")))), "action");
        Bad(b => ((List<object?>)b["services"]!).Add(PolicyFactory.Map(("name", "x"), ("match", PolicyFactory.Map(("base", "ftp://x.example"))), ("ops", PolicyFactory.List()))), "base");
        Bad(b => ((List<object?>)b["services"]!).Add(PolicyFactory.Map(("name", "x"), ("match", PolicyFactory.Map(("inbound", true))), ("ops", PolicyFactory.List()))), "internal");
    }

    [Fact]
    public void NonCanonicalButSignedBodiesAreStillTheSignedBytes()
    {
        // Duplicate keys in the signed bytes are refused (fail closed), whatever the signature says.
        byte[] bytes = Encoding.UTF8.GetBytes("{\"format\":\"tt.policy.body/v1\",\"format\":\"tt.policy.body/v1\"}");
        byte[] prefix = Encoding.Latin1.GetBytes("tt.policy.body/v1\0");
        byte[] sig = TestEd25519.Sign(Key.Seed, prefix.Concat(bytes).ToArray());
        var env = PolicyFactory.Map(
            ("format", "tt.policy.compiled/v1"), ("policy_id", "p-shop"), ("version", new Lex("1")), ("issued_seq", new Lex("1")),
            ("hash", "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()),
            ("body_b64", Utf8Util.B64UrlNoPad(bytes)),
            ("signature", PolicyFactory.Map(("alg", "Ed25519"), ("kid", PolicyFactory.SigningKid), ("sig", Utf8Util.B64UrlNoPad(sig)))));
        Rejected(env, "body json");
    }

    [Fact]
    public void AcceptanceConditions()
    {
        var p = new Policy(PolicyChecks.ValidateBodySchema(Plain.From(JsonParser.Parse(PolicyFactory.BodyBytes(PolicyFactory.Shop(issuedSeq: 5))), true)));
        double now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        PolicyChecks.CheckAcceptance(p, "shop", now, 4, 0);
        Assert.Equal("policy_rejected", Assert.Throws<RefusedException>(() => PolicyChecks.CheckAcceptance(p, "other", now, 4, 0)).Code);
        Assert.Equal("policy_rejected", Assert.Throws<RefusedException>(() => PolicyChecks.CheckAcceptance(p, "shop", now, 5, 0)).Code);
        PolicyChecks.CheckAcceptance(p, "shop", now, 5, 0, allowEqualSeq: true);
        Assert.Equal("policy_rejected", Assert.Throws<RefusedException>(() => PolicyChecks.CheckAcceptance(p, "shop", now, 4, 6)).Code);
        Assert.Equal("expired_policy", Assert.Throws<RefusedException>(() => PolicyChecks.CheckAcceptance(p, "shop", p.NotAfter, 4, 0)).Code);
        Assert.Equal("expired_policy", Assert.Throws<RefusedException>(() => PolicyChecks.CheckAcceptance(p, "shop", double.NaN, 4, 0)).Code);
    }

    [Fact]
    public void HmacKeyRingParsing()
    {
        string k = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        var ring = PolicyChecks.ParseKeyRing("k1:" + k + "\r\n\nk2:" + k + "\nk1:" + new string('A', 43) + "\n");
        Assert.Equal(new[] { "k1", "k2" }, ring.Order);
        Assert.Equal(Utf8Util.B64UrlDecodeStrict(k), ring.Keys["k1"]); // first line wins (A-KEY-DUPLICATE)
        foreach (string bad in new[] { "", "\n\n", "k1:" + k + " ", " k1:" + k, "k1: " + k, "k1:" + k + "=", "k1:" + k.Substring(0, 42), "k1:" + k.Replace('A', '+'), "k123456789:" + k, "k1" })
            Assert.Equal("key_missing", Assert.Throws<RefusedException>(() => PolicyChecks.ParseKeyRing(bad)).Code);
        Assert.Equal("key_missing", Assert.Throws<RefusedException>(() => PolicyChecks.ParseKeyRing(null)).Code);
        // One bad line invalidates the whole configuration (7.1).
        Assert.Throws<RefusedException>(() => PolicyChecks.ParseKeyRing("k1:" + k + "\nbroken"));
    }
}

public class GenerativeLeakTests
{
    /// <summary>G1 (THREAT_MODEL): with the empty policy no VALUE of the exchange appears in the output, whatever it looks like.</summary>
    [Fact]
    public void EmptyPolicyNeverEmitsAValue()
    {
        string root = Paths.Conformance();
        var body = PolicyChecks.ValidateBodySchema(Plain.From(JsonParser.Parse(File.ReadAllBytes(Path.Combine(root, "policies", "empty.json"))), true));
        var policy = new Policy(body);
        var ring = PolicyChecks.ParseKeyRing(PolicyFactory.HmacKeyLine);
        var (kid, key) = PolicyChecks.SelectKey(ring, policy);
        var san = new Sanitizer(policy, kid, key);
        var rnd = new Random(20261023);
        double now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        string[] vocab = { "id", "name", "email", "items", "sku", "qty", "status", "address", "note", "total", "customer", "token", "data" };

        string Secret() => "SECRET" + rnd.Next().ToString("x8") + (char)('a' + rnd.Next(26));
        string Value(List<string> secrets)
        {
            string s = Secret();
            secrets.Add(s);
            return rnd.Next(6) switch
            {
                0 => s,
                1 => s + "@example.com",
                2 => "https://" + s + ".example/x",
                3 => s + " " + s,
                4 => "\u00e8\u00e0" + s,
                _ => s + "-" + rnd.Next(1000000),
            };
        }
        object? Json(int depth, List<string> secrets)
        {
            int kind = rnd.Next(depth > 3 ? 4 : 7);
            switch (kind)
            {
                case 0: return Value(secrets);
                case 1: return rnd.Next(100000);
                case 2: return rnd.Next(2) == 0;
                case 3: return null;
                case 4:
                    {
                        var l = new List<object?>();
                        for (int i = rnd.Next(5); i > 0; i--) l.Add(Json(depth + 1, secrets));
                        return l;
                    }
                default:
                    {
                        var d = new Dictionary<string, object?>();
                        for (int i = rnd.Next(5); i > 0; i--) d[vocab[rnd.Next(vocab.Length)] + (rnd.Next(4) == 0 ? rnd.Next(10_000_000).ToString() : "")] = Json(depth + 1, secrets);
                        return d;
                    }
            }
        }
        string ToJson(object? v) => v switch
        {
            null => "null",
            bool b => b ? "true" : "false",
            int i => i.ToString(),
            string s => System.Text.Json.JsonSerializer.Serialize(s),
            List<object?> l => "[" + string.Join(",", l.Select(ToJson)) + "]",
            Dictionary<string, object?> d => "{" + string.Join(",", d.Select(kv => System.Text.Json.JsonSerializer.Serialize(kv.Key) + ":" + ToJson(kv.Value))) + "}",
            _ => throw new InvalidOperationException(),
        };

        for (int n = 0; n < 1500; n++)
        {
            var secrets = new List<string>();
            // Spec v1.5: a host label is structure only if it passes the label rule (3.5); otherwise it leaves as {*}.
            string hostSecret = Secret().ToLowerInvariant();
            secrets.Add(hostSecret);
            string label = (n % 4) switch
            {
                0 => "t-" + (100000 + rnd.Next(900000)) + "-" + hostSecret,   // rule b: six digits
                1 => hostSecret + "-deadbeef" + rnd.Next(65536).ToString("x4"), // rule c: 12 hex in a row
                2 => "9" + hostSecret,                                         // rule a: starts with a digit
                _ => "tenant" + rnd.Next(100) + "-" + hostSecret + "_x",      // rule a: '_' is not allowed
            };
            var ex = new Exchange { Inbound = n % 2 == 0, ServiceName = "shop-api", UrlBase = "https://" + label + ".cdn.example:" + (1 + rnd.Next(65534)), Method = "POST" };
            var segs = new List<string>();
            for (int i = rnd.Next(5); i > 0; i--) segs.Add(Uri.EscapeDataString(Value(secrets)));
            ex.RawPath = Encoding.UTF8.GetBytes("/" + string.Join("/", segs));
            var q = new List<string>();
            for (int i = rnd.Next(4); i > 0; i--) q.Add(rnd.Next(3) == 0 ? Uri.EscapeDataString(Value(secrets)) : vocab[rnd.Next(vocab.Length)] + "=" + Uri.EscapeDataString(Value(secrets)));
            ex.RawQuery = rnd.Next(4) == 0 ? null : Encoding.UTF8.GetBytes(string.Join("&", q));
            for (int i = rnd.Next(5); i > 0; i--) ex.ReqHeaders.Add((vocab[rnd.Next(vocab.Length)] + "-h", Encoding.UTF8.GetBytes(Value(secrets))));
            ex.ReqHeaders.Add(("Cookie", Encoding.UTF8.GetBytes("sid=" + Value(secrets) + "; theme=" + Value(secrets))));
            ex.ReqHeaders.Add(("Authorization", Encoding.UTF8.GetBytes("Bearer " + Value(secrets))));
            ex.ReqHeaders.Add(("Content-Type", Encoding.UTF8.GetBytes(rnd.Next(3) == 0 ? "application/x-www-form-urlencoded" : "application/json")));
            string reqBody = ex.ReqHeaders[^1].Item2.Length > 20
                ? string.Join("&", Enumerable.Range(0, 3).Select(_ => vocab[rnd.Next(vocab.Length)] + "=" + Uri.EscapeDataString(Value(secrets))))
                : ToJson(Json(0, secrets));
            ex.ReqBody = Encoding.UTF8.GetBytes(reqBody);
            ex.Status = 200 + rnd.Next(400);
            ex.RespHeaders = new() { ("Set-Cookie", Encoding.UTF8.GetBytes("sid=" + Value(secrets) + "; Path=/; HttpOnly")), ("Content-Type", Encoding.UTF8.GetBytes("application/json")), ("X-Trace", Encoding.UTF8.GetBytes(Value(secrets))) };
            ex.RespBody = Encoding.UTF8.GetBytes(ToJson(Json(0, secrets)));
            var r = san.Run(ex, now);
            if (r.Outcome != Outcome.Event) continue;
            if (!ex.Inbound)
            {
                // G1 with host labels: every literal label of the service passes the rule; at most 518 bytes.
                var sm = System.Text.RegularExpressions.Regex.Match(r.Canonical, "\"service\":\"([^\"]*)\"");
                Assert.True(sm.Success, r.Canonical);
                string service = sm.Groups[1].Value;
                Assert.True(Encoding.UTF8.GetByteCount(service) <= 518, service);
                Assert.StartsWith("host:", service);
                string pat = System.Text.RegularExpressions.Regex.Replace(service.Substring(5), ":[0-9]+$", "");
                if (!pat.StartsWith("ip:", StringComparison.Ordinal) && pat != "invalid")
                {
                    foreach (string lab in pat.Split('.')) Assert.True(lab == "{*}" || HostPattern.LabelSafe(lab), "unsafe label " + lab + " in " + service);
                }
            }
            foreach (string s in secrets)
            {
                Assert.DoesNotContain(s, r.Canonical);
                Assert.DoesNotContain(s.ToLowerInvariant(), r.Canonical.ToLowerInvariant());
            }
            // Every string of the output is in the token grammar (6.1) or one of the service fields.
            Assert.DoesNotContain("@example.com", r.Canonical);
        }
    }
}

/// <summary>ARCHITECTURE 3.2: the sources of the SDK must not create activities, listeners, tracer providers or propagators.</summary>
public class SourceHygieneTests
{
    private static string SrcDir([System.Runtime.CompilerServices.CallerFilePath] string thisFile = "")
    {
        foreach (string start in new[] { Path.GetDirectoryName(thisFile) ?? "", AppContext.BaseDirectory, Directory.GetCurrentDirectory() })
        {
            string? d = start;
            while (d != null && !Directory.Exists(Path.Combine(d, "src", "TrafficTwin.Sdk"))) d = Path.GetDirectoryName(d);
            if (d != null) return Path.Combine(d, "src");
        }
        throw new DirectoryNotFoundException("src/ not found");
    }

    [Fact]
    public void NoActivityCreationNoListenersNoGlobalState()
    {
        string[] forbidden =
        {
            "new ActivitySource", "new ActivityListener", "AddActivityListener", "new Activity(", "StartActivity(", "Activity.Current =",
            "TracerProvider", "AddOpenTelemetry", "Propagators", "DistributedContextPropagator", "TextMapPropagator", "OpenTelemetry",
            "Environment.Exit", "Process.Start", "AppDomain.CurrentDomain.UnhandledException", "ServicePointManager", "DefaultProxy",
        };
        foreach (string f in Directory.GetFiles(SrcDir(), "*.cs", SearchOption.AllDirectories).Where(p => !p.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar)))
        {
            var code = File.ReadAllLines(f).Where(l => !l.TrimStart().StartsWith("//", StringComparison.Ordinal)).ToList();
            string text = string.Join("\n", code);
            foreach (string bad in forbidden) Assert.True(!text.Contains(bad, StringComparison.Ordinal), f + " contains " + bad);
            // Nothing is ever logged but codes: no string interpolation into the standard streams.
            Assert.DoesNotContain("Console.Out", text);
        }
    }
}

/// <summary>Shape of GraphQL documents (sanitizer.md 5.7.1), a few cases of the differential corpus of the reference.</summary>
public class GraphQLShapeTests
{
    [Theory]
    [InlineData("query GetOrder($id: ID!) { order(id: $id) { id status items { sku } } }", "query GetOrder($id:ID!){order(id:$id){id status items{sku}}}", false)]
    [InlineData("{ order(id: \"ORD-123\", n: 5, r: 1.5, ok: true, st: SHIPPED, x: null) { id } }", "{order(id:?s n:?i r:?f ok:?b st:?e x:?n){id}}", false)]
    [InlineData("mutation M($in: [OrderIn!]! = [{note: \"urgente\"}]) { a: create(in: $in) { ...F } } fragment F on Order { id }", "mutation M($in:[OrderIn!]!=[{note:?s}]){a:create(in:$in){...F}}fragment F on Order{id}", false)]
    [InlineData("{ o4821553: order(id: 1) { id } }", "{*:order(id:?i){id}}", false)]
    [InlineData("\uFEFF{ a , b }", "{a b}", false)]
    [InlineData("# c\n{ __schema { types { name } } __typename }", "{__schema{types{name}}__typename}", true)]
    [InlineData("{ __schema: order(id: 1) { id } }", "{__schema:order(id:?i){id}}", false)]
    [InlineData("{ a(s: \"\"\"x \\\"\"\" \u00e9\"\"\") }", "{a(s:?s)}", false)]
    public void Shapes(string doc, string shape, bool intro)
    {
        var r = GraphQL.Shape(doc);
        Assert.NotNull(r);
        Assert.Equal(shape, r!.Value.Shape);
        Assert.Equal(intro, r.Value.Introspection);
    }

    [Theory]
    [InlineData("ciao")]
    [InlineData("type Query { a: Int }")]
    [InlineData("{ a(x: 01) }")]
    [InlineData("{ a(x: 1.5.2) }")]
    [InlineData("{ a(x: \"\\q\") }")]
    [InlineData("{ \u00e9 }")]
    [InlineData("{ a }}")]
    [InlineData("{}")]
    [InlineData("query () { a }")]
    public void NotDocuments(string doc) => Assert.Null(GraphQL.Shape(doc));

    [Fact]
    public void Limits()
    {
        // 64 open brackets at most; a shape of at most 32768 bytes.
        Assert.NotNull(GraphQL.Shape("{a(x:" + new string('[', 62) + "1" + new string(']', 62) + ")}"));
        Assert.Null(GraphQL.Shape("{a(x:" + new string('[', 63) + "1" + new string(']', 63) + ")}"));
        Assert.Null(GraphQL.Shape("{" + string.Join(" ", Enumerable.Repeat("abcdefgh", 4000)) + "}"));
    }

    [Theory]
    [InlineData("__Schema", true)]
    [InlineData("String", true)]
    [InlineData("a123456", false)]
    [InlineData("deadbeefdeadbeef", false)]
    [InlineData("not a name", false)]
    public void NameRule(string name, bool safe) => Assert.Equal(safe, GraphQL.IsName(name) && GraphQL.NameSafe(name));
}
