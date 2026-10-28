package io.github.ivseb.traffictwin.sanitizer;

import java.util.regex.Pattern;

/**
 * Shapes (6.2), recognized formats (6.3), length classes (0.3) and the name rule (9.3.3).
 *
 * <p>All patterns are whole-string, ASCII-only matches (0.1): {@code Matcher.matches()} on
 * explicit character classes, no flags.
 */
public final class Formats {
    private Formats() {}

    public static String lenClass(long n) {
        if (n <= 8) return "l8";
        if (n <= 32) return "l32";
        if (n <= 128) return "l128";
        if (n <= 1024) return "l1024";
        return "lmax";
    }

    private static Pattern p(String re) {
        return Pattern.compile(re);
    }

    public static final Pattern UUID = p("[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}");
    public static final Pattern JWT = p("eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*");
    public static final Pattern EMAIL = p("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\\.[A-Za-z0-9-]{1,63})+");
    public static final Pattern DATETIME = p("[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:[0-9]{2})");
    public static final Pattern DATE = p("[0-9]{4}-[0-9]{2}-[0-9]{2}");
    public static final Pattern URL = p("[A-Za-z][A-Za-z0-9+.-]{0,15}://[!-~]+");
    public static final Pattern IPV4 = p("(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}");
    public static final Pattern PHONE = p("\\+[1-9][0-9]{6,14}");
    public static final Pattern DIGITS = p("-?[0-9]{1,19}");
    public static final Pattern HEX = p("[0-9A-Fa-f]{16,}");

    private static final String[] NAMES = {"uuid", "jwt", "email", "datetime", "date", "url", "ipv4", "phone", "digits", "hex"};
    private static final Pattern[] PATTERNS = {UUID, JWT, EMAIL, DATETIME, DATE, URL, IPV4, PHONE, DIGITS, HEX};

    public static boolean isPrintableAscii(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c > 0x7e) return false;
        }
        return true;
    }

    /** First matching format of 6.3, or null. Only printable ASCII strings are considered. */
    public static String detectFormat(String s) {
        if (!isPrintableAscii(s)) return null;
        for (int i = 0; i < PATTERNS.length; i++) {
            if (PATTERNS[i].matcher(s).matches()) return NAMES[i];
        }
        return null;
    }

    /** drop form of a well-formed string. */
    public static String strShape(String s) {
        String f = detectFormat(s);
        if (f != null) return "drop:str:" + f;
        return "drop:str:" + lenClass(Utf8.length(s));
    }

    private static final Pattern KEY = p("[A-Za-z_][A-Za-z0-9_.-]{0,63}");
    private static final Pattern HEADER_NAME = p("[a-z0-9!#$%&'*+.^_`|~-]{1,64}");
    public static final Pattern PATH_TOKEN = p("[A-Za-z0-9._~-]{1,64}");
    /** Code shape of the code action (sanitizer.md 5.6, spec v1.11). */
    public static final Pattern CODE = p("[A-Za-z_-]{2,32}");
    /** Code shape {@code alnum} of the code action (sanitizer.md 5.6, spec v1.19). */
    public static final Pattern CODE_ALNUM = p("[A-Za-z0-9_.-]{1,16}");
    public static final Pattern AUTO_WORD = p("([a-z]+([-_][a-z]+)*|v[0-9]{1,3})");

    private static boolean containsSixDigits(String s) {
        int run = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= '0' && c <= '9') {
                if (++run >= 6) return true;
            } else run = 0;
        }
        return false;
    }

    private static boolean looksLikeValue(String s) {
        return UUID.matcher(s).matches() || EMAIL.matcher(s).matches() || HEX.matcher(s).matches()
            || DIGITS.matcher(s).matches() || JWT.matcher(s).matches() || containsSixDigits(s);
    }

    /** 9.3.3: a JSON key, query, cookie or form name leaves as a literal only if this holds. */
    public static boolean isLiteralName(String s) {
        return KEY.matcher(s).matches() && !looksLikeValue(s);
    }

    /** 8.0.2: output name of a lowercased header name. */
    public static String headerOutName(String lower) {
        if (!HEADER_NAME.matcher(lower).matches() || looksLikeValue(lower)) return "{*}";
        return lower;
    }
}
