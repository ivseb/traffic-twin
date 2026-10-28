package io.github.ivseb.traffictwin.sanitizer;

import java.util.Base64;

/** base64url helpers: strict decoding (alphabet A-Z a-z 0-9 - _, optional nothing else) and encoding without padding. */
public final class Base64Url {
    private Base64Url() {}

    /** Strict base64url without padding; null on any other character or impossible length. */
    public static byte[] decodeStrict(String s) {
        int n = s.length();
        if (n % 4 == 1) return null;
        for (int i = 0; i < n; i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) return null;
        }
        try {
            return Base64.getUrlDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public static String encode(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    public static String encode(byte[] b, int len) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(len == b.length ? b : java.util.Arrays.copyOf(b, len));
    }
}
