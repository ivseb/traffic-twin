using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using TrafficTwin.Sdk.Sanitizing;

namespace TrafficTwin.Sdk.Export;

/// <summary>What the source fills into an event besides the sanitizer output (event.md 1).</summary>
internal sealed class EventMeta
{
    public string PolicyId = "";
    public long PolicyVersion;
    public string PolicyHash = "";
    public string SourceId = "";
    public bool Inbound = true;
    public long TsMs;
    public long LatencyMs;
    public int? Status;
    public string? NetError;
    public string? TraceId;
    public string? SpanId;
    public string? ParentSpanId;
}

internal sealed class QueuedEvent
{
    public string Json = "";
    public long TsMs;
    public string? TraceId;
    public string? SpanId;
    public string PolicyHash = "";
}

/// <summary>Event assembly (event.md 1) and the OTLP/HTTP JSON logs body (event.md 4.2), written by hand.</summary>
internal static class EventBuilder
{
    private static readonly Regex Hex32 = Re.Full("[0-9a-f]{32}");
    private static readonly Regex Hex16 = Re.Full("[0-9a-f]{16}");

    /// <summary>
    /// Full canonical event from the serialized top-level members of the sanitizer output and the fields the source fills.
    /// Null if it is invalid or exceeds 512 KiB (counted as a sanitizer error).
    /// </summary>
    public static string? Build(IReadOnlyDictionary<string, string> sanitized, EventMeta m)
    {
        var parts = new Dictionary<string, string>(sanitized, StringComparer.Ordinal);
        static string S(string v) => Canonical.WriteString(v);
        static string N(long v) => v.ToString(CultureInfo.InvariantCulture);
        parts["schema"] = S("tt.http.exchange/v1");
        parts["policy"] = "{\"hash\":" + S(m.PolicyHash) + ",\"id\":" + S(m.PolicyId) + ",\"version\":" + N(m.PolicyVersion) + "}";
        parts["source"] = "{\"id\":" + S(m.SourceId) + ",\"kind\":" + S(SdkInfo.SourceKind) + ",\"version\":" + S(SdkInfo.Version) + "}";
        parts["ts"] = S(DateTimeOffset.FromUnixTimeMilliseconds(m.TsMs).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture));
        parts["latency_ms"] = N(Math.Max(0, m.LatencyMs));
        parts["dir"] = S(m.Inbound ? "inbound" : "outbound");
        if (m.NetError != null)
        {
            parts["net_error"] = S(m.NetError);
            parts.Remove("resp");
        }
        else if (m.Status is >= 100 and <= 599)
        {
            parts["status"] = N(m.Status.Value);
        }
        else
        {
            return null;
        }
        if (m.TraceId != null && Hex32.IsMatch(m.TraceId)) parts["trace_id"] = S(m.TraceId);
        if (m.SpanId != null && Hex16.IsMatch(m.SpanId)) parts["span_id"] = S(m.SpanId);
        if (m.ParentSpanId != null && Hex16.IsMatch(m.ParentSpanId)) parts["parent_span_id"] = S(m.ParentSpanId);
        string s = Canonical.Compose(parts);
        return s.Length > Sanitizer.MaxEventBytes ? null : s;
    }

    private static readonly JsonWriterOptions WriterOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping, SkipValidation = false };

    private static void Attr(Utf8JsonWriter w, string key, string value)
    {
        w.WriteStartObject();
        w.WriteString("key", key);
        w.WritePropertyName("value");
        w.WriteStartObject();
        w.WriteString("stringValue", value);
        w.WriteEndObject();
        w.WriteEndObject();
    }

    /// <summary>OTLP/HTTP JSON body for a batch of events.</summary>
    public static byte[] OtlpBody(IReadOnlyList<QueuedEvent> events, string serviceName, string sourceId, long nowMs)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms, WriterOptions))
        {
            string observed = (nowMs * 1_000_000L).ToString(CultureInfo.InvariantCulture);
            w.WriteStartObject();
            w.WritePropertyName("resourceLogs");
            w.WriteStartArray();
            w.WriteStartObject();
            w.WritePropertyName("resource");
            w.WriteStartObject();
            w.WritePropertyName("attributes");
            w.WriteStartArray();
            Attr(w, "service.name", serviceName);
            Attr(w, "tt.source.kind", SdkInfo.SourceKind);
            Attr(w, "tt.source.version", SdkInfo.Version);
            Attr(w, "tt.source.id", sourceId);
            w.WriteEndArray();
            w.WriteEndObject();
            w.WritePropertyName("scopeLogs");
            w.WriteStartArray();
            w.WriteStartObject();
            w.WritePropertyName("scope");
            w.WriteStartObject();
            w.WriteString("name", "traffic-twin");
            w.WriteString("version", SdkInfo.Version);
            w.WriteEndObject();
            w.WritePropertyName("logRecords");
            w.WriteStartArray();
            foreach (QueuedEvent e in events)
            {
                w.WriteStartObject();
                w.WriteString("timeUnixNano", (e.TsMs * 1_000_000L).ToString(CultureInfo.InvariantCulture));
                w.WriteString("observedTimeUnixNano", observed);
                w.WriteNumber("severityNumber", 9);
                w.WriteString("severityText", "INFO");
                w.WriteString("eventName", "tt.http.exchange");
                if (e.TraceId != null && Hex32.IsMatch(e.TraceId)) w.WriteString("traceId", e.TraceId);
                if (e.SpanId != null && Hex16.IsMatch(e.SpanId)) w.WriteString("spanId", e.SpanId);
                w.WritePropertyName("attributes");
                w.WriteStartArray();
                Attr(w, "tt.schema", "tt.http.exchange/v1");
                Attr(w, "tt.policy.hash", e.PolicyHash);
                w.WriteEndArray();
                w.WritePropertyName("body");
                w.WriteStartObject();
                w.WriteString("stringValue", e.Json);
                w.WriteEndObject();
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteEndObject();
            w.WriteEndArray();
            w.WriteEndObject();
            w.WriteEndArray();
            w.WriteEndObject();
        }
        return ms.ToArray();
    }
}
