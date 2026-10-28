using System;
using System.Numerics;
using System.Security.Cryptography;

namespace TrafficTwin.Sdk.Sanitizing;

/// <summary>
/// Ed25519 signature verification (RFC 8032, section 5.1.7), written from the RFC. .NET has no built-in
/// Ed25519. Verification only touches public data (public key, message, signature), so a variable-time
/// implementation on <see cref="BigInteger"/> is acceptable here. Signing is NOT part of the SDK.
/// The check is the strict one of RFC 8032 / Go's crypto/ed25519: S &lt; L, canonical public key, and
/// the encoding of [S]B - [k]A must be byte-equal to R.
/// </summary>
internal static class Ed25519
{
    internal static readonly BigInteger P = (BigInteger.One << 255) - 19;
    internal static readonly BigInteger L = (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");
    internal static readonly BigInteger D = Mod(-121665 * Inv(121666));
    private static readonly BigInteger SqrtM1 = BigInteger.ModPow(2, (P - 1) / 4, P);

    /// <summary>A point in extended homogeneous coordinates (X:Y:Z:T), x = X/Z, y = Y/Z, xy = T/Z.</summary>
    internal readonly record struct Point(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T);

    internal static readonly Point Base = MakeBase();

    internal static BigInteger Mod(BigInteger a)
    {
        BigInteger r = BigInteger.Remainder(a, P);
        return r.Sign < 0 ? r + P : r;
    }

    internal static BigInteger Inv(BigInteger a) => BigInteger.ModPow(Mod(a), P - 2, P);

    private static Point MakeBase()
    {
        BigInteger y = Mod(4 * Inv(5));
        BigInteger? x = RecoverX(y, 0);
        return new Point(x!.Value, y, BigInteger.One, Mod(x.Value * y));
    }

    private static BigInteger? RecoverX(BigInteger y, int sign)
    {
        if (y >= P) return null;
        BigInteger x2 = Mod((y * y - 1) * Inv(D * y * y + 1));
        if (x2.IsZero) return sign != 0 ? null : BigInteger.Zero;
        BigInteger x = BigInteger.ModPow(x2, (P + 3) / 8, P);
        if (!Mod(x * x - x2).IsZero) x = Mod(x * SqrtM1);
        if (!Mod(x * x - x2).IsZero) return null;
        if ((int)(x & 1) != sign) x = P - x;
        return x;
    }

    internal static Point Add(Point p, Point q)
    {
        BigInteger a = Mod((p.Y - p.X) * (q.Y - q.X));
        BigInteger b = Mod((p.Y + p.X) * (q.Y + q.X));
        BigInteger c = Mod(2 * p.T * q.T * D);
        BigInteger d = Mod(2 * p.Z * q.Z);
        BigInteger e = b - a, f = d - c, g = d + c, h = b + a;
        return new Point(Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    internal static Point Mul(BigInteger s, Point p)
    {
        var q = new Point(BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero);
        while (s > 0)
        {
            if (!s.IsEven) q = Add(q, p);
            p = Add(p, p);
            s >>= 1;
        }
        return q;
    }

    internal static byte[] Compress(Point p)
    {
        BigInteger zinv = Inv(p.Z);
        BigInteger x = Mod(p.X * zinv);
        BigInteger y = Mod(p.Y * zinv);
        BigInteger v = y | ((x & 1) << 255);
        return ToLe32(v);
    }

    internal static byte[] ToLe32(BigInteger v)
    {
        var raw = v.ToByteArray(isUnsigned: true, isBigEndian: false);
        var outp = new byte[32];
        Array.Copy(raw, outp, Math.Min(raw.Length, 32));
        return outp;
    }

    internal static BigInteger FromLe(ReadOnlySpan<byte> b) => new(b, isUnsigned: true, isBigEndian: false);

    internal static Point? Decompress(ReadOnlySpan<byte> s)
    {
        if (s.Length != 32) return null;
        BigInteger y = FromLe(s);
        int sign = (int)(y >> 255);
        y &= (BigInteger.One << 255) - 1;
        BigInteger? x = RecoverX(y, sign);
        if (x == null) return null;
        return new Point(x.Value, y, BigInteger.One, Mod(x.Value * y));
    }

    internal static BigInteger HashModL(params byte[][] parts)
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        foreach (var p in parts) h.AppendData(p);
        return FromLe(h.GetHashAndReset()) % L;
    }

    /// <summary>Verifies an Ed25519 signature (64 bytes) over <paramref name="message"/> with a raw 32-byte public key.</summary>
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != 32 || signature.Length != 64) return false;
        Point? a = Decompress(publicKey);
        if (a == null) return false;
        // Canonical encoding of A (RFC 8032 5.1.3 allows rejecting a non-canonical y).
        if (!Compress(a.Value).AsSpan().SequenceEqual(publicKey)) return false;
        BigInteger s = FromLe(signature.Slice(32));
        if (s >= L) return false;
        byte[] r = signature.Slice(0, 32).ToArray();
        BigInteger k = HashModL(r, publicKey.ToArray(), message.ToArray());
        Point sb = Mul(s, Base);
        Point negA = new(Mod(-a.Value.X), a.Value.Y, a.Value.Z, Mod(-a.Value.T));
        Point ka = Mul(k, negA);
        Point rCheck = Add(sb, ka);
        return Compress(rCheck).AsSpan().SequenceEqual(r);
    }
}
