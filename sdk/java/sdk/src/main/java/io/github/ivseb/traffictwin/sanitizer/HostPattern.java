package io.github.ivseb.traffictwin.sanitizer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Host patterns (sanitizer.md 3.1 point 5, 3.5, 3.6; spec v1.5): the IPv6 literal parser, the IPv4/IPv6
 * class tables and the label rule. Everything is written out here on purpose: no library classification
 * ({@code InetAddress}, {@code isSiteLocalAddress}, ...) is used, because it changes between JDKs.
 */
public final class HostPattern {
    private HostPattern() {}

    // ---------------------------------------------------------------------------------
    // 3.1 point 5: IPv6 literal (RFC 4291 2.2 text form, own parser)

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    /** One dotted IPv4 (6.3 {@code ipv4}: four 0-255 parts, no leading zeros) into 4 ints, or null. */
    static int[] parseIpv4(String s) {
        int[] out = new int[4];
        int idx = 0;
        int i = 0;
        int n = s.length();
        while (true) {
            int start = i;
            int val = 0;
            while (i < n && isDigit(s.charAt(i))) {
                val = val * 10 + (s.charAt(i) - '0');
                i++;
                if (i - start > 3) return null;
            }
            int len = i - start;
            if (len == 0 || (len > 1 && s.charAt(start) == '0') || val > 255) return null;
            out[idx++] = val;
            if (idx == 4) return i == n ? out : null;
            if (i >= n || s.charAt(i) != '.') return null;
            i++;
        }
    }

    private static String[] splitColon(String s) {
        return s.isEmpty() ? new String[0] : s.split(":", -1);
    }

    /** Appends the groups of {@code parts} to {@code out}; the last one may be a dotted IPv4 when {@code tailOk}. */
    private static boolean groups(String[] parts, boolean tailOk, List<Integer> out) {
        for (int k = 0; k < parts.length; k++) {
            String g = parts[k];
            if (tailOk && k == parts.length - 1 && g.indexOf('.') >= 0) {
                int[] o = parseIpv4(g);
                if (o == null) return false;
                out.add((o[0] << 8) | o[1]);
                out.add((o[2] << 8) | o[3]);
            } else {
                if (g.isEmpty() || g.length() > 4) return false;
                int v = 0;
                for (int i = 0; i < g.length(); i++) {
                    char c = g.charAt(i);
                    if (!isHex(c)) return false;
                    v = (v << 4) | Character.digit(c, 16);
                }
                out.add(v);
            }
        }
        return true;
    }

    /**
     * Parses the (lowercase) text between the brackets: 1-4 hex digit groups, at most one {@code ::} standing for at
     * least one zero group (so at most 7 written groups with it, exactly 8 without), an optional IPv4 tail as the last
     * element, no zone. Returns the 16 bytes or null.
     */
    public static byte[] parseIpv6(String s) {
        int first = s.indexOf("::");
        if (first >= 0 && s.indexOf("::", first + 2) >= 0) return null;
        List<Integer> g = new ArrayList<>(8);
        if (first >= 0) {
            List<Integer> a = new ArrayList<>();
            List<Integer> b = new ArrayList<>();
            if (!groups(splitColon(s.substring(0, first)), false, a)) return null;
            if (!groups(splitColon(s.substring(first + 2)), true, b)) return null;
            if (a.size() + b.size() > 7) return null;
            g.addAll(a);
            for (int i = a.size() + b.size(); i < 8; i++) g.add(0);
            g.addAll(b);
        } else {
            if (!groups(s.split(":", -1), true, g) || g.size() != 8) return null;
        }
        byte[] out = new byte[16];
        for (int i = 0; i < 8; i++) {
            out[2 * i] = (byte) (g.get(i) >> 8);
            out[2 * i + 1] = (byte) (g.get(i) & 0xff);
        }
        return out;
    }

    // ---------------------------------------------------------------------------------
    // 3.6: closed class table

    private static boolean inPrefix(byte[] addr, int[] prefix, int bits) {
        for (int i = 0; i < bits; i++) {
            int a = (addr[i / 8] >> (7 - i % 8)) & 1;
            int p = (prefix[i / 8] >> (7 - i % 8)) & 1;
            if (a != p) return false;
        }
        return true;
    }

    /** IPv4 private ranges: address bytes, then the prefix length. */
    private static final int[][] V4_PRIVATE = {
        {0, 0, 0, 0, 8}, {10, 0, 0, 0, 8}, {100, 64, 0, 0, 10}, {127, 0, 0, 0, 8}, {169, 254, 0, 0, 16},
        {172, 16, 0, 0, 12}, {192, 0, 0, 0, 24}, {192, 0, 2, 0, 24}, {192, 168, 0, 0, 16}, {198, 18, 0, 0, 15},
        {198, 51, 100, 0, 24}, {203, 0, 113, 0, 24}, {224, 0, 0, 0, 4}, {240, 0, 0, 0, 4}};

    /** IPv6 private ranges: the leading bytes of the prefix, padded to 13 entries, then the prefix length (all are at most 96 bits). */
    private static final int[][] V6_PRIVATE = {
        v6(96),                                       // ::/96
        v6(48, 0x00, 0x64, 0xff, 0x9b, 0x00, 0x01),   // 64:ff9b:1::/48
        v6(64, 0x01, 0x00),                           // 100::/64
        v6(23, 0x20, 0x01),                           // 2001::/23
        v6(32, 0x20, 0x01, 0x0d, 0xb8),               // 2001:db8::/32
        v6(7, 0xfc),                                  // fc00::/7
        v6(10, 0xfe, 0x80),                           // fe80::/10
        v6(10, 0xfe, 0xc0),                           // fec0::/10
        v6(8, 0xff)};                                 // ff00::/8

    private static int[] v6(int bits, int... lead) {
        int[] r = new int[13];
        System.arraycopy(lead, 0, r, 0, lead.length);
        r[12] = bits;
        return r;
    }

    private static final int[] V4MAPPED = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};   // ::ffff:0:0/96
    private static final int[] NAT64 = {0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0}; // 64:ff9b::/96

    public static boolean ipv4Private(byte[] a4) {
        for (int[] r : V4_PRIVATE) if (inPrefix(a4, r, r[4])) return true;
        return false;
    }

    public static boolean ipv6Private(byte[] a16) {
        // The two ranges with an embedded IPv4 come first (3.6): the class is the one of the last 32 bits.
        if (inPrefix(a16, V4MAPPED, 96) || inPrefix(a16, NAT64, 96)) {
            return ipv4Private(Arrays.copyOfRange(a16, 12, 16));
        }
        for (int[] r : V6_PRIVATE) if (inPrefix(a16, r, r[12])) return true;
        return false;
    }

    // ---------------------------------------------------------------------------------
    // 3.5: label rule and pattern

    /** Rules a-d of 3.5 (d is implied by c for a string that passes a, but is evaluated anyway). */
    public static boolean labelSafe(String label) {
        int n = label.length();
        if (n < 1 || n > 63) return false;
        char c0 = label.charAt(0);
        if (c0 < 'a' || c0 > 'z') return false;
        int digits = 0;
        int hex = 0;
        for (int i = 0; i < n; i++) {
            char c = label.charAt(i);
            boolean d = isDigit(c);
            if (!(d || (c >= 'a' && c <= 'z') || c == '-')) return false;
            digits = d ? digits + 1 : 0;
            hex = (d || (c >= 'a' && c <= 'f')) ? hex + 1 : 0;
            if (digits >= 6 || hex >= 12) return false;
        }
        return Formats.detectFormat(label) == null;
    }

    /**
     * The pattern of a valid host ({@code host} lowercase, possibly with one final dot; {@code port} without leading
     * zeros, or "" when absent or default; {@code ip6} the 16 bytes of a bracketed literal, else null), or null when a
     * label is empty (service {@code host:invalid}).
     */
    public static String pattern(String host, String port, byte[] ip6) {
        String suffix = port == null || port.isEmpty() ? "" : ":" + port;
        if (ip6 != null) return "ip:" + (ipv6Private(ip6) ? "private" : "public") + suffix;
        String h = host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
        String[] labels = h.split("\\.", -1);
        for (String l : labels) if (l.isEmpty()) return null;
        int[] v4 = parseIpv4(h);
        if (v4 != null) {
            byte[] a = {(byte) v4[0], (byte) v4[1], (byte) v4[2], (byte) v4[3]};
            return "ip:" + (ipv4Private(a) ? "private" : "public") + suffix;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < labels.length; i++) {
            if (i > 0) sb.append('.');
            sb.append(labelSafe(labels[i]) ? labels[i] : "{*}");
        }
        return sb.append(suffix).toString();
    }
}
