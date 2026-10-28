using System.Text.RegularExpressions;

namespace TrafficTwin.Sdk.Sanitizing;

/// <summary>Whole-string, ASCII-only regular expressions (sanitizer.md 0.1): anchors are \A and \z, never "$".</summary>
internal static class Re
{
    public static Regex Full(string pattern, RegexOptions extra = RegexOptions.None) =>
        new(@"\A(?:" + pattern + @")\z", RegexOptions.CultureInvariant | extra);

    public static Regex Find(string pattern, RegexOptions extra = RegexOptions.None) =>
        new(pattern, RegexOptions.CultureInvariant | extra);
}
