using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using TrafficTwin.Sdk.Sanitizing;

namespace TrafficTwin.Sdk.Capture;

/// <summary>
/// The inbound exchange being served, flowed to outbound calls through an <see cref="AsyncLocal{T}"/>
/// (event.md 1.1, sanitizer.md 12): same trace id, inherited sampling decision.
/// </summary>
internal sealed class ExchangeCtx
{
    public bool Sampled;
    public string TraceId = "";
    /// <summary>True when <see cref="TraceId"/> came from the request (traceparent) or from the ambient <see cref="Activity"/>.</summary>
    public bool TraceKnown;
    public string SpanId = "";
}

internal static class ExchangeContext
{
    private static readonly AsyncLocal<ExchangeCtx?> Slot = new();

    public static ExchangeCtx? Current
    {
        get => Slot.Value;
        set => Slot.Value = value;
    }

    // Ids come from a per-thread pool filled by the CSPRNG: one system call per 256 ids instead of one per id.
    [ThreadStatic] private static byte[]? pool;
    [ThreadStatic] private static int poolOff;
    private const int PoolSize = 4096;

    private static string NonZeroHex(int bytes)
    {
        for (;;)
        {
            if (pool == null || poolOff + bytes > PoolSize)
            {
                pool ??= new byte[PoolSize];
                RandomNumberGenerator.Fill(pool);
                poolOff = 0;
            }
            ReadOnlySpan<byte> b = pool.AsSpan(poolOff, bytes);
            poolOff += bytes;
            bool zero = true;
            foreach (byte x in b)
            {
                if (x != 0) { zero = false; break; }
            }
            if (!zero) return Convert.ToHexString(b).ToLowerInvariant();
        }
    }

    public static string NewTraceId() => NonZeroHex(16);

    public static string NewSpanId() => NonZeroHex(8);

    private static readonly Regex TraceparentRe = Re.Full("([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(-.*)?", RegexOptions.Singleline);

    /// <summary>W3C trace context: ids from a traceparent value, or null if invalid.</summary>
    public static (string TraceId, string SpanId)? ParseTraceparent(string? v)
    {
        if (v == null) return null;
        Match m = TraceparentRe.Match(v.Trim(' ', '\t'));
        if (!m.Success) return null;
        string ver = m.Groups[1].Value;
        if (ver == "ff" || (ver == "00" && m.Groups[5].Success)) return null;
        string t = m.Groups[2].Value, s = m.Groups[3].Value;
        if (IsAllZero(t) || IsAllZero(s)) return null;
        return (t, s);
    }

    private static bool IsAllZero(string s)
    {
        foreach (char c in s)
        {
            if (c != '0') return false;
        }
        return true;
    }

    /// <summary>
    /// The ambient <see cref="Activity"/> (OpenTelemetry or ASP.NET Core's own), READ ONLY: this SDK never creates activities,
    /// registers an <see cref="ActivityListener"/>, a TracerProvider or a propagator.
    /// </summary>
    public static (string TraceId, string SpanId, string? ParentSpanId)? ActiveActivity()
    {
        try
        {
            Activity? a = Activity.Current;
            if (a == null || a.IdFormat != ActivityIdFormat.W3C) return null;
            string t = a.TraceId.ToHexString();
            if (IsAllZero(t)) return null;
            string s = a.SpanId.ToHexString();
            string? parent = a.ParentSpanId == default ? null : a.ParentSpanId.ToHexString();
            return (t, IsAllZero(s) ? "" : s, parent);
        }
        catch (Exception)
        {
            return null;
        }
    }
}
