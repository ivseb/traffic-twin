using System;
using System.Numerics;
using System.Security.Cryptography;
using TrafficTwin.Sdk.Sanitizing;

namespace TrafficTwin.Sdk.Tests.Helpers;

/// <summary>Ed25519 SIGNING for tests only (RFC 8032 5.1.6), on the primitives of the SDK. The SDK itself only verifies.</summary>
internal static class TestEd25519
{
    private static (BigInteger A, byte[] Prefix) Expand(byte[] seed)
    {
        byte[] h = SHA512.HashData(seed);
        byte[] a = h.AsSpan(0, 32).ToArray();
        a[0] &= 248;
        a[31] &= 127;
        a[31] |= 64;
        return (Ed25519.FromLe(a), h.AsSpan(32, 32).ToArray());
    }

    public static byte[] PublicKey(byte[] seed)
    {
        var (a, _) = Expand(seed);
        return Ed25519.Compress(Ed25519.Mul(a, Ed25519.Base));
    }

    public static (byte[] Seed, byte[] Public) NewKey()
    {
        byte[] seed = RandomNumberGenerator.GetBytes(32);
        return (seed, PublicKey(seed));
    }

    public static byte[] Sign(byte[] seed, byte[] message)
    {
        var (a, prefix) = Expand(seed);
        byte[] pub = Ed25519.Compress(Ed25519.Mul(a, Ed25519.Base));
        BigInteger r = Ed25519.HashModL(prefix, message);
        byte[] rEnc = Ed25519.Compress(Ed25519.Mul(r, Ed25519.Base));
        BigInteger k = Ed25519.HashModL(rEnc, pub, message);
        BigInteger s = (r + k * a) % Ed25519.L;
        var sig = new byte[64];
        rEnc.CopyTo(sig, 0);
        Ed25519.ToLe32(s).CopyTo(sig, 32);
        return sig;
    }
}
