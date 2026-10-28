using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace TrafficTwin.Sdk.Sanitizing;

/// <summary>
/// Shapes (6.2), recognized formats (6.3), length classes (0.3) and the name rule (9.3.3).
/// The expressions are compile-time generated, whole-string and ASCII-only (0.1: anchors are \A and \z, never "$"). Each one is
/// preceded by a cheap necessary condition (length, first character) so that most strings never reach the regex engine; the
/// guards only exclude strings the expression could not match.
/// </summary>
internal static partial class Formats
{
    public static string LenClass(long n)
    {
        if (n <= 8) return "l8";
        if (n <= 32) return "l32";
        if (n <= 128) return "l128";
        if (n <= 1024) return "l1024";
        return "lmax";
    }

    private const RegexOptions O = RegexOptions.CultureInvariant;

    [GeneratedRegex(@"\A(?:[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\z", O)]
    private static partial Regex UuidRe();

    [GeneratedRegex(@"\A(?:eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)\z", O)]
    private static partial Regex JwtRe();

    [GeneratedRegex(@"\A(?:[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+)\z", O)]
    private static partial Regex EmailRe();

    [GeneratedRegex(@"\A(?:[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:[0-9]{2}))\z", O)]
    private static partial Regex DateTimeRe();

    [GeneratedRegex(@"\A(?:[0-9]{4}-[0-9]{2}-[0-9]{2})\z", O)]
    private static partial Regex DateRe();

    [GeneratedRegex(@"\A(?:[A-Za-z][A-Za-z0-9+.-]{0,15}://[!-~]+)\z", O)]
    private static partial Regex UrlRe();

    [GeneratedRegex(@"\A(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})\z", O)]
    private static partial Regex Ipv4Re();

    [GeneratedRegex(@"\A(?:\+[1-9][0-9]{6,14})\z", O)]
    private static partial Regex PhoneRe();

    [GeneratedRegex(@"\A(?:-?[0-9]{1,19})\z", O)]
    private static partial Regex DigitsRe();

    [GeneratedRegex(@"\A(?:[0-9A-Fa-f]{16,})\z", O)]
    private static partial Regex HexRe();

    [GeneratedRegex(@"\A(?:[A-Za-z_][A-Za-z0-9_.-]{0,63})\z", O)]
    private static partial Regex KeyRe();

    [GeneratedRegex(@"[0-9]{6}", O)]
    private static partial Regex SixDigitsRe();

    [GeneratedRegex(@"\A(?:[a-z0-9!#$%&'*+.^_`|~-]{1,64})\z", O)]
    private static partial Regex HeaderNameRe();

    [GeneratedRegex(@"\A(?:[A-Za-z0-9._~-]{1,64})\z", O)]
    private static partial Regex PathTokenRe();

    // Code shape of the code action (sanitizer.md 5.6, spec v1.11).
    [GeneratedRegex(@"\A(?:[A-Za-z_-]{2,32})\z", O)]
    private static partial Regex CodeRe();

    // Shape alnum of the code action (sanitizer.md 5.6, spec v1.19).
    [GeneratedRegex(@"\A(?:[A-Za-z0-9_.-]{1,16})\z", O)]
    private static partial Regex CodeAlnumRe();

    [GeneratedRegex(@"\A(?:([a-z]+([-_][a-z]+)*|v[0-9]{1,3}))\z", O)]
    private static partial Regex AutoWordRe();

    public static bool IsUuid(string s) => s.Length == 36 && UuidRe().IsMatch(s);
    public static bool IsJwt(string s) => s.Length >= 6 && s[0] == 'e' && s[1] == 'y' && s[2] == 'J' && JwtRe().IsMatch(s);
    public static bool IsEmail(string s) => s.Length >= 5 && s.Contains('@') && EmailRe().IsMatch(s);
    public static bool IsDateTime(string s) => s.Length >= 20 && s[4] == '-' && DateTimeRe().IsMatch(s);
    public static bool IsDate(string s) => s.Length == 10 && s[4] == '-' && DateRe().IsMatch(s);
    public static bool IsUrl(string s) => s.Length >= 4 && s.Contains("://", System.StringComparison.Ordinal) && UrlRe().IsMatch(s);
    public static bool IsIpv4(string s) => s.Length >= 7 && s.Length <= 15 && s.Contains('.') && Ipv4Re().IsMatch(s);
    public static bool IsPhone(string s) => s.Length >= 8 && s[0] == '+' && PhoneRe().IsMatch(s);
    public static bool IsDigits(string s) => s.Length >= 1 && s.Length <= 20 && (s[0] == '-' || (s[0] >= '0' && s[0] <= '9')) && DigitsRe().IsMatch(s);
    public static bool IsHex(string s) => s.Length >= 16 && HexRe().IsMatch(s);

    public static bool IsPrintableAscii(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] < 0x20 || s[i] > 0x7e) return false;
        }
        return true;
    }

    /// <summary>First matching format of 6.3, or null. Only printable ASCII strings are considered.</summary>
    public static string? DetectFormat(string s)
    {
        if (!IsPrintableAscii(s)) return null;
        if (IsUuid(s)) return "uuid";
        if (IsJwt(s)) return "jwt";
        if (IsEmail(s)) return "email";
        if (IsDateTime(s)) return "datetime";
        if (IsDate(s)) return "date";
        if (IsUrl(s)) return "url";
        if (IsIpv4(s)) return "ipv4";
        if (IsPhone(s)) return "phone";
        if (IsDigits(s)) return "digits";
        if (IsHex(s)) return "hex";
        return null;
    }

    /// <summary>drop form of a well-formed string.</summary>
    public static string StrShape(string s)
    {
        string? f = DetectFormat(s);
        if (f != null) return "drop:str:" + f;
        return "drop:str:" + LenClass(Utf8Util.Utf8Length(s));
    }

    public static bool DateTimeMatches(string s) => IsDateTime(s);
    public static bool DateMatches(string s) => IsDate(s);

    private static bool LooksLikeValue(string s) => IsUuid(s) || IsEmail(s) || IsHex(s) || IsDigits(s) || IsJwt(s) || SixDigitsRe().IsMatch(s);

    // Names are low-cardinality in practice (the same few header, key and query names, over and over): their decision is cached,
    // with a size cap so that an attacker who sends endless distinct names cannot grow it.
    private const int NameCacheMax = 8192;
    private static readonly ConcurrentDictionary<string, bool> LiteralCache = new(System.StringComparer.Ordinal);
    private static readonly ConcurrentDictionary<string, string> HeaderCache = new(System.StringComparer.Ordinal);

    /// <summary>9.3.3: a JSON key, query, cookie or form name leaves as a literal only if this holds.</summary>
    public static bool IsLiteralName(string s)
    {
        if (LiteralCache.TryGetValue(s, out bool v)) return v;
        v = s.Length >= 1 && s.Length <= 64 && KeyRe().IsMatch(s) && !LooksLikeValue(s);
        if (LiteralCache.Count < NameCacheMax) LiteralCache[s] = v;
        return v;
    }

    /// <summary>8.0.2: output name of a lowercased header name.</summary>
    public static string HeaderOutName(string lower)
    {
        if (HeaderCache.TryGetValue(lower, out string? v)) return v;
        v = !HeaderNameRe().IsMatch(lower) || LooksLikeValue(lower) ? "{*}" : lower;
        if (HeaderCache.Count < NameCacheMax) HeaderCache[lower] = v;
        return v;
    }

    public static bool IsPathToken(string s) => s.Length >= 1 && s.Length <= 64 && PathTokenRe().IsMatch(s);

    public static bool IsCode(string s) => s.Length >= 2 && s.Length <= 32 && CodeRe().IsMatch(s);

    public static bool IsCodeAlnum(string s) => s.Length >= 1 && s.Length <= 16 && CodeAlnumRe().IsMatch(s);

    public static bool IsAutoWord(string s) => s.Length >= 1 && AutoWordRe().IsMatch(s);
}
