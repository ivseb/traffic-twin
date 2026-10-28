package io.github.ivseb.traffictwin.sanitizer;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * Strict UTF-8 (RFC 3629, sanitizer.md 0.2) and byte helpers.
 *
 * <p>The JDK UTF-8 decoder in REPORT mode rejects overlong forms, encoded surrogates and code
 * points above U+10FFFF, and does not treat a byte order mark specially.
 */
public final class Utf8 {
    private Utf8() {}

    private static final ThreadLocal<CharsetDecoder> DECODER = ThreadLocal.withInitial(
        () -> StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT));

    /** Decodes strictly; returns null when the bytes are not valid UTF-8. */
    public static String decode(byte[] b) {
        return decode(b, 0, b.length);
    }

    public static String decode(byte[] b, int off, int len) {
        if (len == 0) return "";
        boolean ascii = true;
        for (int i = off; i < off + len; i++) {
            if (b[i] < 0) {
                ascii = false;
                break;
            }
        }
        if (ascii) return new String(b, off, len, StandardCharsets.ISO_8859_1);
        CharsetDecoder d = DECODER.get();
        d.reset();
        try {
            CharBuffer cb = d.decode(ByteBuffer.wrap(b, off, len));
            return cb.toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    public static byte[] encode(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** UTF-8 length of a well-formed string. */
    public static int length(String s) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x80) n++;
            else if (c < 0x800) n += 2;
            else if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                n += 4;
                i++;
            } else n += 3;
        }
        return n;
    }

    /** True when the string has no unpaired surrogate (so it has a UTF-8 encoding). */
    public static boolean isWellFormed(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) i++;
                else return false;
            } else if (Character.isLowSurrogate(c)) {
                return false;
            }
        }
        return true;
    }

    /** ASCII-only lowercase (never touches non-ASCII characters). */
    public static String asciiLower(String s) {
        int i = 0;
        int n = s.length();
        while (i < n) {
            char c = s.charAt(i);
            if (c >= 'A' && c <= 'Z') break;
            i++;
        }
        if (i == n) return s;
        char[] a = s.toCharArray();
        for (; i < n; i++) if (a[i] >= 'A' && a[i] <= 'Z') a[i] += 32;
        return new String(a);
    }

    public static String asciiUpper(String s) {
        char[] a = s.toCharArray();
        for (int i = 0; i < a.length; i++) if (a[i] >= 'a' && a[i] <= 'z') a[i] -= 32;
        return new String(a);
    }

    /** Strips OWS (space and horizontal tab) on both sides. */
    public static byte[] trimOws(byte[] b) {
        int s = 0;
        int e = b.length;
        while (s < e && (b[s] == 0x20 || b[s] == 0x09)) s++;
        while (e > s && (b[e - 1] == 0x20 || b[e - 1] == 0x09)) e--;
        if (s == 0 && e == b.length) return b;
        return java.util.Arrays.copyOfRange(b, s, e);
    }

    public static String trimOws(String s) {
        int a = 0;
        int e = s.length();
        while (a < e && (s.charAt(a) == 0x20 || s.charAt(a) == 0x09)) a++;
        while (e > a && (s.charAt(e - 1) == 0x20 || s.charAt(e - 1) == 0x09)) e--;
        return s.substring(a, e);
    }

    public static int indexOf(byte[] b, int value) {
        return indexOf(b, value, 0);
    }

    public static int indexOf(byte[] b, int value, int from) {
        for (int i = from; i < b.length; i++) if (b[i] == (byte) value) return i;
        return -1;
    }

    public static byte[] slice(byte[] b, int from, int to) {
        if (from == 0 && to == b.length) return b;
        return java.util.Arrays.copyOfRange(b, from, to);
    }

    /** Splits bytes on a single byte value (keeps empty parts). */
    public static java.util.List<byte[]> split(byte[] b, int sep) {
        java.util.List<byte[]> out = new java.util.ArrayList<>();
        int start = 0;
        for (int i = 0; i < b.length; i++) {
            if (b[i] == (byte) sep) {
                out.add(java.util.Arrays.copyOfRange(b, start, i));
                start = i + 1;
            }
        }
        out.add(java.util.Arrays.copyOfRange(b, start, b.length));
        return out;
    }

    public static byte[] concat(java.util.List<byte[]> parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    private static int hexVal(int c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    }

    /** Percent-decoding of sanitizer.md 4.1 (optionally "+" to space first, 8.3). */
    public static byte[] pctDecode(byte[] b, boolean plusIsSpace) {
        boolean needs = false;
        for (byte x : b) {
            if (x == '%' || (plusIsSpace && x == '+')) {
                needs = true;
                break;
            }
        }
        if (!needs) return b;
        byte[] out = new byte[b.length];
        int o = 0;
        for (int i = 0; i < b.length; i++) {
            int c = b[i] & 0xff;
            if (c == '%' && i + 2 < b.length) {
                int h = hexVal(b[i + 1] & 0xff);
                int l = hexVal(b[i + 2] & 0xff);
                if (h >= 0 && l >= 0) {
                    out[o++] = (byte) (h * 16 + l);
                    i += 2;
                    continue;
                }
            }
            out[o++] = (byte) (plusIsSpace && c == '+' ? 0x20 : c);
        }
        return java.util.Arrays.copyOf(out, o);
    }

    /** Byte-order comparison of two strings by their UTF-8 encoding (code point order). */
    public static int cmp(String a, String b) {
        int n = Math.min(a.length(), b.length());
        for (int i = 0; i < n; i++) {
            int x = a.charAt(i);
            int y = b.charAt(i);
            if (x == y) continue;
            // Surrogates (supplementary code points) sort after U+E000..U+FFFF in UTF-8.
            if (x >= 0xd800 && x <= 0xdfff) x += 0x10000;
            if (y >= 0xd800 && y <= 0xdfff) y += 0x10000;
            return x < y ? -1 : 1;
        }
        return Integer.compare(a.length(), b.length());
    }

    public static int cmp(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) {
            int x = a[i] & 0xff;
            int y = b[i] & 0xff;
            if (x != y) return x < y ? -1 : 1;
        }
        return Integer.compare(a.length, b.length);
    }
}
