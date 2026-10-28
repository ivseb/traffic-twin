using System;
using System.IO;
using TrafficTwin.Sdk.Sanitizing;
using Xunit;

namespace TrafficTwin.Sdk.Tests;

public class Ed25519Tests
{
    private static byte[] Hex(string s) => Convert.FromHexString(s);

    private static readonly string[] Lines = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "TestData", "ed25519-vectors.txt"));

    [Fact]
    public void Rfc8032Test1_EmptyMessage()
    {
        var f = Lines[0].Split(':');
        Assert.Equal("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", f[0]);
        Assert.True(Ed25519.Verify(Hex(f[0]), Hex(f[1]), Hex(f[2])));
    }

    [Fact]
    public void Rfc8032Test2_OneByte()
    {
        Assert.True(Ed25519.Verify(
            Hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"), Hex("72"),
            Hex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")));
    }

    [Fact]
    public void Rfc8032Test3_TwoBytes()
    {
        var f = Lines[2].Split(':');
        Assert.Equal("af82", f[1]);
        Assert.True(Ed25519.Verify(Hex(f[0]), Hex(f[1]), Hex(f[2])));
    }

    [Fact]
    public void AllReferenceVectorsVerify()
    {
        foreach (string line in Lines)
        {
            var f = line.Split(':');
            Assert.True(Ed25519.Verify(Hex(f[0]), Hex(f[1]), Hex(f[2])), "vector " + f[0]);
        }
        Assert.Equal(128, Lines.Length);
    }

    [Fact]
    public void RejectsAlteredMessageSignatureAndKey()
    {
        var f = Lines[5].Split(':');
        byte[] pk = Hex(f[0]), msg = Hex(f[1]), sig = Hex(f[2]);
        Assert.True(Ed25519.Verify(pk, msg, sig));
        var m2 = (byte[])msg.Clone();
        if (m2.Length == 0) m2 = new byte[] { 1 }; else m2[0] ^= 1;
        Assert.False(Ed25519.Verify(pk, m2, sig));
        var s2 = (byte[])sig.Clone();
        s2[0] ^= 1;
        Assert.False(Ed25519.Verify(pk, msg, s2));
        var s3 = (byte[])sig.Clone();
        s3[40] ^= 1;
        Assert.False(Ed25519.Verify(pk, msg, s3));
        var k2 = (byte[])pk.Clone();
        k2[3] ^= 1;
        Assert.False(Ed25519.Verify(k2, msg, sig));
    }

    [Fact]
    public void RejectsMalleableSignature()
    {
        // S + L is a different encoding of the same scalar: RFC 8032 requires S < L.
        var f = Lines[1].Split(':');
        byte[] pk = Hex(f[0]), msg = Hex(f[1]), sig = Hex(f[2]);
        var s = Ed25519.FromLe(sig.AsSpan(32));
        var s2 = Ed25519.ToLe32(s + Ed25519.L);
        var bad = new byte[64];
        Array.Copy(sig, bad, 32);
        Array.Copy(s2, 0, bad, 32, 32);
        Assert.False(Ed25519.Verify(pk, msg, bad));
    }

    [Fact]
    public void RejectsWrongLengths()
    {
        var f = Lines[0].Split(':');
        Assert.False(Ed25519.Verify(Hex(f[0]).AsSpan(0, 31), Hex(f[1]), Hex(f[2])));
        Assert.False(Ed25519.Verify(Hex(f[0]), Hex(f[1]), Hex(f[2]).AsSpan(0, 63)));
    }
}
