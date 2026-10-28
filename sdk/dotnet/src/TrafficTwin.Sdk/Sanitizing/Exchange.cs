using System;
using System.Collections.Generic;

namespace TrafficTwin.Sdk.Sanitizing;

/// <summary>Normalized exchange (sanitizer.md 1). Bodies and header values are bytes; names are strings as the runtime shows them.</summary>
internal sealed class Exchange
{
    /// <summary>Value of a <c>*_body_total</c> that is unknown at the end of the exchange.</summary>
    public const long UnknownTotal = -1;

    public bool Inbound = true;
    public string? ServiceName;
    public string? UrlBase;
    public string Method = "";
    public byte[] RawPath = Array.Empty<byte>();
    /// <summary>null = the URL had no "?".</summary>
    public byte[]? RawQuery;
    /// <summary>A-FRAMEWORK-ID: identifier of the 3.4 table; required with <see cref="FrameworkRoute"/>.</summary>
    public string? Framework;
    public string? FrameworkRoute;
    public string? TraceId;
    public bool? Inherited;
    public List<(string Name, byte[] Value)> ReqHeaders = new();
    public byte[]? ReqBody;
    public long? ReqBodyTotal;
    public bool? ReqBodyConsumed;
    public bool? ReqBodyDecoded;
    public int? Status;
    /// <summary>timeout | reset | refused | dns | tls | other</summary>
    public string? NetError;
    public List<(string Name, byte[] Value)>? RespHeaders;
    public byte[]? RespBody;
    public long? RespBodyTotal;
    public bool? RespBodyConsumed;
    public bool? RespBodyDecoded;
}

internal readonly record struct Decision(bool Sampled, string By);

internal enum Outcome { Event, NotSampled, TooLarge }

internal sealed class SanitizeResult
{
    public Outcome Outcome;
    public string SampledBy = "";
    public Dictionary<string, object?>? Out;
    /// <summary>Top-level members already serialized (the source assembles the full event from them).</summary>
    public Dictionary<string, string>? Parts;
    public string Canonical = "";
}
