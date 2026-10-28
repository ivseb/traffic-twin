using System;
using System.Collections.Generic;
using System.Text;

namespace TrafficTwin.Sdk.Sanitizing;

/// <summary>Strict UTF-8 (RFC 3629, sanitizer.md 0.2) and byte/ASCII helpers. All operations are ordinal.</summary>
internal static class Utf8Util
{
    private static readonly UTF8Encoding Strict = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>Decodes strictly (no overlong forms, surrogates or code points above U+10FFFF); null when invalid. A BOM stays a character.</summary>
    public static string? Decode(ReadOnlySpan<byte> b)
    {
        if (b.Length == 0) return "";
        bool ascii = true;
        for (int i = 0; i < b.Length; i++)
        {
            if (b[i] >= 0x80) { ascii = false; break; }
        }
        if (ascii) return Encoding.Latin1.GetString(b);
        try { return Strict.GetString(b); }
        catch (DecoderFallbackException) { return null; }
    }

    /// <summary>True when the string has no lone surrogates (so it has a UTF-8 encoding).</summary>
    public static bool IsWellFormed(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { i++; continue; }
                return false;
            }
            if (char.IsLowSurrogate(c)) return false;
        }
        return true;
    }

    public static int Utf8Length(string s) => Strict.GetByteCount(s);

    public static byte[] Utf8(string s) => Strict.GetBytes(s);

    public static byte[] Latin1(string s) => Encoding.Latin1.GetBytes(s);

    public static string Latin1(ReadOnlySpan<byte> b) => Encoding.Latin1.GetString(b);

    /// <summary>ASCII-only lowercase (never touches non-ASCII characters).</summary>
    public static string AsciiLower(string s)
    {
        int first = -1;
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] >= 'A' && s[i] <= 'Z') { first = i; break; }
        }
        if (first < 0) return s;
        return string.Create(s.Length, s, static (span, src) =>
        {
            for (int i = 0; i < span.Length; i++)
            {
                char c = src[i];
                span[i] = c >= 'A' && c <= 'Z' ? (char)(c + 32) : c;
            }
        });
    }

    /// <summary>True when AsciiLower(<paramref name="a"/>) equals <paramref name="lowerB"/> (which is already lowercase ASCII); no allocation.</summary>
    public static bool EqualsAsciiLower(string a, string lowerB)
    {
        if (a.Length != lowerB.Length) return false;
        for (int i = 0; i < a.Length; i++)
        {
            char c = a[i];
            if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
            if (c != lowerB[i]) return false;
        }
        return true;
    }

    public static string AsciiUpper(string s)
    {
        return string.Create(s.Length, s, static (span, src) =>
        {
            for (int i = 0; i < span.Length; i++)
            {
                char c = src[i];
                span[i] = c >= 'a' && c <= 'z' ? (char)(c - 32) : c;
            }
        });
    }

    /// <summary>Strips OWS (space and horizontal tab) on both sides.</summary>
    public static byte[] TrimOws(byte[] b)
    {
        int s = 0, e = b.Length;
        while (s < e && (b[s] == 0x20 || b[s] == 0x09)) s++;
        while (e > s && (b[e - 1] == 0x20 || b[e - 1] == 0x09)) e--;
        if (s == 0 && e == b.Length) return b;
        return b.AsSpan(s, e - s).ToArray();
    }

    public static string TrimOwsStr(string s)
    {
        int a = 0, e = s.Length;
        while (a < e && (s[a] == ' ' || s[a] == '\t')) a++;
        while (e > a && (s[e - 1] == ' ' || s[e - 1] == '\t')) e--;
        return a == 0 && e == s.Length ? s : s.Substring(a, e - a);
    }

    /// <summary>Splits bytes on a single byte value (keeps empty parts).</summary>
    public static List<byte[]> Split(byte[] b, byte sep)
    {
        var res = new List<byte[]>();
        int start = 0;
        for (int i = 0; i < b.Length; i++)
        {
            if (b[i] == sep)
            {
                res.Add(b.AsSpan(start, i - start).ToArray());
                start = i + 1;
            }
        }
        res.Add(b.AsSpan(start).ToArray());
        return res;
    }

    public static int IndexOf(byte[] b, byte v) => Array.IndexOf(b, v);

    public static byte[] Slice(byte[] b, int start, int length) => b.AsSpan(start, length).ToArray();

    private static int HexVal(byte c)
    {
        if (c >= 0x30 && c <= 0x39) return c - 0x30;
        if (c >= 0x41 && c <= 0x46) return c - 0x37;
        if (c >= 0x61 && c <= 0x66) return c - 0x57;
        return -1;
    }

    /// <summary>Percent-decoding of sanitizer.md 4.1 (optionally "+" to space first, 8.3).</summary>
    public static byte[] PctDecode(byte[] b, bool plusIsSpace)
    {
        bool needs = false;
        for (int i = 0; i < b.Length; i++)
        {
            if (b[i] == 0x25 || (plusIsSpace && b[i] == 0x2b)) { needs = true; break; }
        }
        if (!needs) return b;
        var outp = new byte[b.Length];
        int o = 0;
        for (int i = 0; i < b.Length; i++)
        {
            byte c = b[i];
            if (c == 0x25 && i + 2 < b.Length)
            {
                int h = HexVal(b[i + 1]);
                int l = HexVal(b[i + 2]);
                if (h >= 0 && l >= 0)
                {
                    outp[o++] = (byte)(h * 16 + l);
                    i += 2;
                    continue;
                }
            }
            outp[o++] = plusIsSpace && c == 0x2b ? (byte)0x20 : c;
        }
        return outp.AsSpan(0, o).ToArray();
    }

    /// <summary>Byte-order comparison of two strings by their UTF-8 encoding (code point order).</summary>
    public static int CmpUtf8(string a, string b)
    {
        int n = Math.Min(a.Length, b.Length);
        for (int i = 0; i < n; i++)
        {
            int x = a[i];
            int y = b[i];
            if (x == y) continue;
            // Surrogates (supplementary code points) sort after U+E000..U+FFFF in UTF-8.
            if (x >= 0xd800 && x <= 0xdfff) x += 0x10000;
            if (y >= 0xd800 && y <= 0xdfff) y += 0x10000;
            return x < y ? -1 : 1;
        }
        return a.Length == b.Length ? 0 : a.Length < b.Length ? -1 : 1;
    }

    private static readonly char[] B64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".ToCharArray();

    /// <summary>base64url without padding.</summary>
    public static string B64UrlNoPad(ReadOnlySpan<byte> b)
    {
        var sb = new StringBuilder((b.Length * 4 + 2) / 3);
        int i = 0;
        for (; i + 2 < b.Length; i += 3)
        {
            int v = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
            sb.Append(B64Chars[(v >> 18) & 63]).Append(B64Chars[(v >> 12) & 63]).Append(B64Chars[(v >> 6) & 63]).Append(B64Chars[v & 63]);
        }
        if (b.Length - i == 1)
        {
            int v = b[i] << 16;
            sb.Append(B64Chars[(v >> 18) & 63]).Append(B64Chars[(v >> 12) & 63]);
        }
        else if (b.Length - i == 2)
        {
            int v = (b[i] << 16) | (b[i + 1] << 8);
            sb.Append(B64Chars[(v >> 18) & 63]).Append(B64Chars[(v >> 12) & 63]).Append(B64Chars[(v >> 6) & 63]);
        }
        return sb.ToString();
    }

    /// <summary>Strict base64url without padding (alphabet A-Z a-z 0-9 - _); null on any other character or impossible length.</summary>
    public static byte[]? B64UrlDecodeStrict(string s)
    {
        if (s.Length % 4 == 1) return null;
        var outp = new byte[s.Length * 3 / 4];
        int o = 0;
        int acc = 0, bits = 0;
        foreach (char ch in s)
        {
            int v;
            if (ch >= 'A' && ch <= 'Z') v = ch - 'A';
            else if (ch >= 'a' && ch <= 'z') v = ch - 'a' + 26;
            else if (ch >= '0' && ch <= '9') v = ch - '0' + 52;
            else if (ch == '-') v = 62;
            else if (ch == '_') v = 63;
            else return null;
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                outp[o++] = (byte)((acc >> bits) & 0xff);
            }
        }
        return outp.AsSpan(0, o).ToArray();
    }

    public static string HexLower(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();
}
