using System;
using TrafficTwin.Sdk.Sanitizing;

namespace TrafficTwin.Sdk.Capture;

/// <summary>A finished exchange, converted to sanitizer input lazily (off the request path).</summary>
internal sealed class RawExchange
{
    public Sanitizer Sanitizer = null!;
    public Decision Decision;
    public Func<Exchange> Build = null!;
    public bool Inbound;
    public long TsMs;
    public long LatencyMs;
    public string? TraceId;
    public string? SpanId;
    public string? ParentSpanId;
    public int? Status;
    public string? NetError;
    /// <summary>Bytes held by this exchange (queue accounting).</summary>
    public long HeldBytes;
}

/// <summary>What the capture hooks need from the agent. Every method must be cheap and never throw.</summary>
internal interface ICaptureHost
{
    /// <summary>Current sanitizer when capture is allowed, else null (fast path).</summary>
    Sanitizer? Active();
    string ServiceName { get; }
    /// <summary>Header names (lowercase) needed for the inbound sampling decision.</summary>
    System.Collections.Generic.IReadOnlySet<string> DecisionHeaders { get; }
    /// <summary>Whether tt.s may be added to the baggage of a call to this url base (sanitizer.md 12).</summary>
    bool MayPropagate(string urlBase);
    void Submit(RawExchange raw);
    void NoteSeen();
    void NoteSampled();
    void NoteOverhead(long ns);
    void NoteError(string code);
}
