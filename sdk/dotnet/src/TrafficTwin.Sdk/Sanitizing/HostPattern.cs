using System;
using System.Collections.Generic;
using System.Text;

namespace TrafficTwin.Sdk.Sanitizing;

/// <summary>
/// Host patterns (sanitizer.md 3.1 point 5, 3.5, 3.6; spec v1.5): the IPv6 literal parser, the IPv4/IPv6 class tables and the
/// label rule. Written out on purpose: no <c>IPAddress.TryParse</c>, no <c>IsIPv6SiteLocal</c> or similar, because the
/// forms they accept and classify change between runtimes.
/// </summary>
internal static class HostPattern
{
    private static bool IsHexChar(char c) => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');

    private static bool IsDigit(char c) => c >= '0' && c <= '9';

    /// <summary>One dotted IPv4 (6.3 <c>ipv4</c>: four 0-255 parts, no leading zeros) into 4 numbers, or null.</summary>
    public static int[]? ParseIpv4(string s)
    {
        var o = new int[4];
        int idx = 0, i = 0, n = s.Length;
        while (true)
        {
            int start = i, val = 0;
            while (i < n && IsDigit(s[i]))
            {
                val = val * 10 + (s[i] - '0');
                i++;
                if (i - start > 3) return null;
            }
            int len = i - start;
            if (len == 0 || (len > 1 && s[start] == '0') || val > 255) return null;
            o[idx++] = val;
            if (idx == 4) return i == n ? o : null;
            if (i >= n || s[i] != '.') return null;
            i++;
        }
    }

    private static string[] SplitColon(string s) => s.Length == 0 ? Array.Empty<string>() : s.Split(':');

    private static bool Groups(string[] parts, bool tailOk, List<int> output)
    {
        for (int k = 0; k < parts.Length; k++)
        {
            string g = parts[k];
            if (tailOk && k == parts.Length - 1 && g.Contains('.'))
            {
                int[]? o = ParseIpv4(g);
                if (o == null) return false;
                output.Add((o[0] << 8) | o[1]);
                output.Add((o[2] << 8) | o[3]);
            }
            else
            {
                if (g.Length == 0 || g.Length > 4) return false;
                int v = 0;
                foreach (char c in g)
                {
                    if (!IsHexChar(c)) return false;
                    v = (v << 4) | (c <= '9' ? c - '0' : c - 'a' + 10);
                }
                output.Add(v);
            }
        }
        return true;
    }

    /// <summary>
    /// Parses the (lowercase) text between the brackets: 1-4 hex digit groups, at most one <c>::</c> standing for at least one zero
    /// group (so at most 7 written groups with it, exactly 8 without), an optional IPv4 tail as the last element, no zone.
    /// Returns the 16 bytes or null.
    /// </summary>
    public static byte[]? ParseIpv6(string s)
    {
        int first = s.IndexOf("::", StringComparison.Ordinal);
        if (first >= 0 && s.IndexOf("::", first + 2, StringComparison.Ordinal) >= 0) return null;
        var g = new List<int>(8);
        if (first >= 0)
        {
            var a = new List<int>();
            var b = new List<int>();
            if (!Groups(SplitColon(s.Substring(0, first)), false, a)) return null;
            if (!Groups(SplitColon(s.Substring(first + 2)), true, b)) return null;
            if (a.Count + b.Count > 7) return null;
            g.AddRange(a);
            for (int i = a.Count + b.Count; i < 8; i++) g.Add(0);
            g.AddRange(b);
        }
        else
        {
            if (!Groups(s.Split(':'), true, g) || g.Count != 8) return null;
        }
        var outp = new byte[16];
        for (int i = 0; i < 8; i++)
        {
            outp[2 * i] = (byte)(g[i] >> 8);
            outp[2 * i + 1] = (byte)(g[i] & 0xff);
        }
        return outp;
    }

    // --- 3.6: closed class table ----------------------------------------------------------

    private static bool InPrefix(ReadOnlySpan<byte> addr, ReadOnlySpan<byte> prefix, int bits)
    {
        for (int i = 0; i < bits; i++)
        {
            int a = (addr[i / 8] >> (7 - i % 8)) & 1;
            int p = (prefix[i / 8] >> (7 - i % 8)) & 1;
            if (a != p) return false;
        }
        return true;
    }

    /// <summary>IPv4 private ranges: address bytes, then the prefix length.</summary>
    private static readonly byte[][] V4Private =
    {
        new byte[] { 0, 0, 0, 0, 8 }, new byte[] { 10, 0, 0, 0, 8 }, new byte[] { 100, 64, 0, 0, 10 }, new byte[] { 127, 0, 0, 0, 8 },
        new byte[] { 169, 254, 0, 0, 16 }, new byte[] { 172, 16, 0, 0, 12 }, new byte[] { 192, 0, 0, 0, 24 }, new byte[] { 192, 0, 2, 0, 24 },
        new byte[] { 192, 168, 0, 0, 16 }, new byte[] { 198, 18, 0, 0, 15 }, new byte[] { 198, 51, 100, 0, 24 }, new byte[] { 203, 0, 113, 0, 24 },
        new byte[] { 224, 0, 0, 0, 4 }, new byte[] { 240, 0, 0, 0, 4 },
    };

    private static byte[] P(params byte[] lead)
    {
        var r = new byte[12];
        Array.Copy(lead, r, lead.Length);
        return r;
    }

    private static readonly (byte[] Prefix, int Bits)[] V6Private =
    {
        (P(), 96),                                    // ::/96
        (P(0x00, 0x64, 0xff, 0x9b, 0x00, 0x01), 48),  // 64:ff9b:1::/48
        (P(0x01, 0x00), 64),                          // 100::/64
        (P(0x20, 0x01), 23),                          // 2001::/23
        (P(0x20, 0x01, 0x0d, 0xb8), 32),              // 2001:db8::/32
        (P(0xfc), 7),                                 // fc00::/7
        (P(0xfe, 0x80), 10),                          // fe80::/10
        (P(0xfe, 0xc0), 10),                          // fec0::/10
        (P(0xff), 8),                                 // ff00::/8
    };

    private static readonly byte[] V4Mapped = P(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff);   // ::ffff:0:0/96
    private static readonly byte[] Nat64 = P(0x00, 0x64, 0xff, 0x9b);                       // 64:ff9b::/96

    public static bool Ipv4Private(ReadOnlySpan<byte> a4)
    {
        foreach (byte[] r in V4Private)
        {
            if (InPrefix(a4, r, r[4])) return true;
        }
        return false;
    }

    public static bool Ipv6Private(byte[] a16)
    {
        // The two ranges with an embedded IPv4 come first (3.6): the class is the one of the last 32 bits.
        if (InPrefix(a16, V4Mapped, 96) || InPrefix(a16, Nat64, 96)) return Ipv4Private(new ReadOnlySpan<byte>(a16, 12, 4));
        foreach (var (prefix, bits) in V6Private)
        {
            if (InPrefix(a16, prefix, bits)) return true;
        }
        return false;
    }

    // --- 3.5: label rule and pattern ------------------------------------------------------

    /// <summary>Rules a-d of 3.5 (d is implied by c for a string that passes a, but is evaluated anyway).</summary>
    public static bool LabelSafe(string label)
    {
        int n = label.Length;
        if (n < 1 || n > 63) return false;
        char c0 = label[0];
        if (c0 < 'a' || c0 > 'z') return false;
        int digits = 0, hex = 0;
        foreach (char c in label)
        {
            bool d = IsDigit(c);
            if (!(d || (c >= 'a' && c <= 'z') || c == '-')) return false;
            digits = d ? digits + 1 : 0;
            hex = (d || (c >= 'a' && c <= 'f')) ? hex + 1 : 0;
            if (digits >= 6 || hex >= 12) return false;
        }
        return Formats.DetectFormat(label) == null;
    }

    /// <summary>
    /// The pattern of a valid host (<paramref name="host"/> lowercase, possibly with one final dot; <paramref name="port"/> without
    /// leading zeros, or "" when absent or default; <paramref name="ip6"/> the 16 bytes of a bracketed literal, else null), or null
    /// when a label is empty (service <c>host:invalid</c>).
    /// </summary>
    public static string? Pattern(string host, string port, byte[]? ip6)
    {
        string suffix = port.Length == 0 ? "" : ":" + port;
        if (ip6 != null) return "ip:" + (Ipv6Private(ip6) ? "private" : "public") + suffix;
        string h = host.EndsWith('.') ? host.Substring(0, host.Length - 1) : host;
        string[] labels = h.Split('.');
        foreach (string l in labels)
        {
            if (l.Length == 0) return null;
        }
        int[]? v4 = ParseIpv4(h);
        if (v4 != null)
        {
            var a = new byte[] { (byte)v4[0], (byte)v4[1], (byte)v4[2], (byte)v4[3] };
            return "ip:" + (Ipv4Private(a) ? "private" : "public") + suffix;
        }
        var sb = new StringBuilder(h.Length + suffix.Length + 8);
        for (int i = 0; i < labels.Length; i++)
        {
            if (i > 0) sb.Append('.');
            sb.Append(LabelSafe(labels[i]) ? labels[i] : "{*}");
        }
        return sb.Append(suffix).ToString();
    }
}
