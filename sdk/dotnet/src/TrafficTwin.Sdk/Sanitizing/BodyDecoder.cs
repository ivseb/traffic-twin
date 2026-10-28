using System;
using System.Collections.Generic;

namespace TrafficTwin.Sdk.Sanitizing;

/// <summary>
/// One-level gzip / zlib decoding for sanitizer.md 9.0 with an output cap (A-GZIP-STRICT). Written on top of an own
/// inflate (RFC 1951) so that the result does not depend on the runtime zlib: a stream that does not end, has bytes
/// after its end, or fails its checksum is an error, and reaching the cap is not.
/// </summary>
internal static class BodyDecoder
{
    internal enum Status { Ok, Cap, Error }

    internal readonly record struct Result(Status Status, byte[]? Data);

    /// <summary>Decodes <paramref name="data"/>. <paramref name="zlibFormat"/> selects RFC 1950 (deflate), else gzip.</summary>
    public static Result Decode(byte[] data, bool zlibFormat, long cap)
    {
        try
        {
            return zlibFormat ? DecodeZlib(data, cap) : DecodeGzip(data, cap);
        }
        catch (InvalidDataException2)
        {
            return new Result(Status.Error, null);
        }
    }

    private sealed class InvalidDataException2 : Exception { }

    private sealed class CapReached : Exception { }

    private static Result DecodeGzip(byte[] d, long cap)
    {
        if (d.Length < 18 || d[0] != 0x1f || d[1] != 0x8b || d[2] != 8) return Err();
        int flg = d[3];
        if ((flg & 0xe0) != 0) return Err();
        int p = 10;
        if ((flg & 4) != 0)
        {
            if (p + 2 > d.Length) return Err();
            int xlen = d[p] | (d[p + 1] << 8);
            p += 2 + xlen;
        }
        if ((flg & 8) != 0) { p = SkipZ(d, p); if (p < 0) return Err(); }
        if ((flg & 16) != 0) { p = SkipZ(d, p); if (p < 0) return Err(); }
        if ((flg & 2) != 0)
        {
            if (p + 2 > d.Length) return Err();
            uint hcrc = Crc32(d.AsSpan(0, p), 0);
            if ((hcrc & 0xffff) != (uint)(d[p] | (d[p + 1] << 8))) return Err();
            p += 2;
        }
        if (p > d.Length - 8) return Err();
        byte[] outp;
        int end;
        try
        {
            var inf = new Inflater(d, p, d.Length - 8, cap);
            outp = inf.Run();
            end = inf.Position;
        }
        catch (CapReached)
        {
            return new Result(Status.Cap, null);
        }
        if (end != d.Length - 8) return Err();
        uint crc = (uint)(d[end] | (d[end + 1] << 8) | (d[end + 2] << 16) | (d[end + 3] << 24));
        uint isize = (uint)(d[end + 4] | (d[end + 5] << 8) | (d[end + 6] << 16) | (d[end + 7] << 24));
        if (crc != Crc32(outp, 0) || isize != (uint)outp.Length) return Err();
        return new Result(Status.Ok, outp);
    }

    private static Result DecodeZlib(byte[] d, long cap)
    {
        if (d.Length < 6) return Err();
        int cmf = d[0], flg = d[1];
        if ((cmf & 0x0f) != 8 || (cmf >> 4) > 7 || ((cmf << 8) | flg) % 31 != 0 || (flg & 0x20) != 0) return Err();
        byte[] outp;
        int end;
        try
        {
            var inf = new Inflater(d, 2, d.Length - 4, cap);
            outp = inf.Run();
            end = inf.Position;
        }
        catch (CapReached)
        {
            return new Result(Status.Cap, null);
        }
        if (end != d.Length - 4) return Err();
        uint adler = (uint)((d[end] << 24) | (d[end + 1] << 16) | (d[end + 2] << 8) | d[end + 3]);
        if (adler != Adler32(outp)) return Err();
        return new Result(Status.Ok, outp);
    }

    private static Result Err() => new(Status.Error, null);

    private static int SkipZ(byte[] d, int p)
    {
        while (p < d.Length && d[p] != 0) p++;
        return p >= d.Length ? -1 : p + 1;
    }

    private static readonly uint[] CrcTable = MakeCrcTable();

    private static uint[] MakeCrcTable()
    {
        var t = new uint[256];
        for (uint n = 0; n < 256; n++)
        {
            uint c = n;
            for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xedb88320u ^ (c >> 1) : c >> 1;
            t[n] = c;
        }
        return t;
    }

    internal static uint Crc32(ReadOnlySpan<byte> b, uint init)
    {
        uint c = ~init;
        foreach (byte x in b) c = CrcTable[(c ^ x) & 0xff] ^ (c >> 8);
        return ~c;
    }

    internal static uint Adler32(ReadOnlySpan<byte> b)
    {
        uint a = 1, s = 0;
        foreach (byte x in b)
        {
            a = (a + x) % 65521;
            s = (s + a) % 65521;
        }
        return (s << 16) | a;
    }

    /// <summary>Inflate (RFC 1951) over a byte range, with an output cap.</summary>
    private sealed class Inflater
    {
        private readonly byte[] src;
        private int pos;
        private readonly int limit;
        private uint bitBuf;
        private int bitCnt;
        private byte[] outp = new byte[1024];
        private int outLen;
        private readonly long cap;

        public Inflater(byte[] data, int start, int endExclusive, long cap)
        {
            src = data;
            pos = start;
            limit = endExclusive;
            this.cap = cap;
        }

        /// <summary>Position of the first unread byte after the final block (partial bits of the last byte are discarded).</summary>
        public int Position => pos;

        private int Bits(int need)
        {
            while (bitCnt < need)
            {
                if (pos >= limit) throw new InvalidDataException2();
                bitBuf |= (uint)src[pos++] << bitCnt;
                bitCnt += 8;
            }
            int v = (int)(bitBuf & ((1u << need) - 1));
            bitBuf >>= need;
            bitCnt -= need;
            return v;
        }

        private void Put(byte b)
        {
            if (outLen >= cap) throw new CapReached();
            if (outLen == outp.Length) Array.Resize(ref outp, (int)Math.Min(int.MaxValue / 2, (long)outp.Length * 2));
            outp[outLen++] = b;
            if (outLen >= cap) throw new CapReached();
        }

        private sealed class Huffman
        {
            public readonly short[] Count = new short[16];
            public readonly short[] Symbol;

            public Huffman(ReadOnlySpan<byte> lengths)
            {
                Symbol = new short[lengths.Length];
                foreach (byte l in lengths) Count[l]++;
                if (Count[0] == lengths.Length) return; // no codes (allowed)
                int left = 1;
                for (int len = 1; len <= 15; len++)
                {
                    left <<= 1;
                    left -= Count[len];
                    if (left < 0) throw new InvalidDataException2(); // over-subscribed
                }
                var offs = new short[16];
                for (int len = 1; len < 15; len++) offs[len + 1] = (short)(offs[len] + Count[len]);
                for (int sym = 0; sym < lengths.Length; sym++)
                {
                    if (lengths[sym] != 0) Symbol[offs[lengths[sym]]++] = (short)sym;
                }
            }
        }

        private int DecodeSym(Huffman h)
        {
            int code = 0, first = 0, index = 0;
            for (int len = 1; len <= 15; len++)
            {
                code |= Bits(1);
                int count = h.Count[len];
                if (code - count < first) return h.Symbol[index + (code - first)];
                index += count;
                first += count;
                first <<= 1;
                code <<= 1;
            }
            throw new InvalidDataException2();
        }

        private static readonly short[] LenBase = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
        private static readonly short[] LenExtra = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
        private static readonly short[] DistBase = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
        private static readonly short[] DistExtra = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };
        private static readonly byte[] ClOrder = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

        private static Huffman? fixedLit, fixedDist;

        private void Codes(Huffman lit, Huffman dist)
        {
            for (;;)
            {
                int sym = DecodeSym(lit);
                if (sym < 256) { Put((byte)sym); continue; }
                if (sym == 256) return;
                sym -= 257;
                if (sym >= 29) throw new InvalidDataException2();
                int len = LenBase[sym] + Bits(LenExtra[sym]);
                int ds = DecodeSym(dist);
                if (ds >= 30) throw new InvalidDataException2();
                int distance = DistBase[ds] + Bits(DistExtra[ds]);
                if (distance > outLen) throw new InvalidDataException2();
                for (int i = 0; i < len; i++) Put(outp[outLen - distance]);
            }
        }

        public byte[] Run()
        {
            bool last;
            do
            {
                last = Bits(1) == 1;
                int type = Bits(2);
                switch (type)
                {
                    case 0: Stored(); break;
                    case 1:
                        if (fixedLit == null)
                        {
                            var l = new byte[288];
                            for (int i = 0; i < 144; i++) l[i] = 8;
                            for (int i = 144; i < 256; i++) l[i] = 9;
                            for (int i = 256; i < 280; i++) l[i] = 7;
                            for (int i = 280; i < 288; i++) l[i] = 8;
                            var dl = new byte[30];
                            Array.Fill(dl, (byte)5);
                            fixedDist = new Huffman(dl);
                            fixedLit = new Huffman(l);
                        }
                        Codes(fixedLit, fixedDist!);
                        break;
                    case 2: Dynamic(); break;
                    default: throw new InvalidDataException2();
                }
            } while (!last);
            // Discard the unused bits of the last byte; whole unread bytes held in the bit buffer are given back.
            pos -= bitCnt / 8;
            bitBuf = 0;
            bitCnt = 0;
            var res = new byte[outLen];
            Array.Copy(outp, res, outLen);
            return res;
        }

        private void Stored()
        {
            bitBuf = 0;
            bitCnt = 0;
            if (pos + 4 > limit) throw new InvalidDataException2();
            int len = src[pos] | (src[pos + 1] << 8);
            int nlen = src[pos + 2] | (src[pos + 3] << 8);
            pos += 4;
            if (len != (~nlen & 0xffff)) throw new InvalidDataException2();
            if (pos + len > limit) throw new InvalidDataException2();
            for (int i = 0; i < len; i++) Put(src[pos++]);
        }

        private void Dynamic()
        {
            int nlen = Bits(5) + 257;
            int ndist = Bits(5) + 1;
            int ncode = Bits(4) + 4;
            if (nlen > 286 || ndist > 30) throw new InvalidDataException2();
            var lengths = new byte[320];
            for (int i = 0; i < ncode; i++) lengths[ClOrder[i]] = (byte)Bits(3);
            var cl = new Huffman(lengths.AsSpan(0, 19));
            // A complete code is required for the code-length code (zlib: "invalid code lengths set").
            if (!IsCompleteOrEmpty(cl, 19, requireComplete: true)) throw new InvalidDataException2();
            var all = new byte[nlen + ndist];
            int idx = 0;
            while (idx < nlen + ndist)
            {
                int sym = DecodeSym(cl);
                if (sym < 16) all[idx++] = (byte)sym;
                else
                {
                    int rep, val = 0;
                    if (sym == 16)
                    {
                        if (idx == 0) throw new InvalidDataException2();
                        val = all[idx - 1];
                        rep = 3 + Bits(2);
                    }
                    else if (sym == 17) rep = 3 + Bits(3);
                    else rep = 11 + Bits(7);
                    if (idx + rep > nlen + ndist) throw new InvalidDataException2();
                    while (rep-- > 0) all[idx++] = (byte)val;
                }
            }
            if (all[256] == 0) throw new InvalidDataException2(); // no end-of-block code
            var lit = new Huffman(all.AsSpan(0, nlen));
            var dist = new Huffman(all.AsSpan(nlen, ndist));
            // Literal/length code must be complete unless it has a single code; distance code likewise (zlib semantics).
            if (!IsCompleteOrEmpty(lit, nlen, requireComplete: false, allowSingle: true)) throw new InvalidDataException2();
            if (!IsCompleteOrEmpty(dist, ndist, requireComplete: false, allowSingle: true)) throw new InvalidDataException2();
            Codes(lit, dist);
        }

        private static bool IsCompleteOrEmpty(Huffman h, int n, bool requireComplete, bool allowSingle = false)
        {
            int left = 1;
            int total = 0;
            for (int len = 1; len <= 15; len++)
            {
                left <<= 1;
                left -= h.Count[len];
                total += h.Count[len];
            }
            if (left == 0) return true;            // complete
            if (requireComplete) return false;
            if (total == 0) return true;           // no codes at all (distance code of a literal-only block)
            return allowSingle && total == 1 && h.Count[1] == 1; // a single one-bit code
        }
    }
}
