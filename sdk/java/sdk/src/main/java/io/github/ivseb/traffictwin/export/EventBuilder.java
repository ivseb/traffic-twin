package io.github.ivseb.traffictwin.export;

import io.github.ivseb.traffictwin.Version;
import io.github.ivseb.traffictwin.sanitizer.Json;
import io.github.ivseb.traffictwin.sanitizer.Sanitizer;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/** Event assembly (event.md 1) and the OTLP/HTTP JSON logs body (event.md 4.2), written by hand. */
public final class EventBuilder {
    private EventBuilder() {}

    /** Fields the source fills around the sanitizer output. */
    public static final class Meta {
        public String policyId = "";
        public long policyVersion;
        public String policyHash = "";
        public String sourceId = "";
        public boolean inbound;
        public long tsMs;
        public long latencyMs;
        /** -1 = absent. */
        public int status = -1;
        public String netError;
        public String traceId;
        public String spanId;
        public String parentSpanId;
    }

    private static final Pattern HEX32 = Pattern.compile("[0-9a-f]{32}");
    private static final Pattern HEX16 = Pattern.compile("[0-9a-f]{16}");
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    /**
     * Full canonical event from the serialized members of the sanitizer output and the fields the
     * source fills. Null if the event is invalid or exceeds 512 KiB (counted as sanitizer error).
     */
    public static String buildEvent(Map<String, String> sanitized, Meta m) {
        Map<String, String> parts = new LinkedHashMap<>(sanitized);
        parts.put("schema", Json.quote("tt.http.exchange/v1"));
        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("id", m.policyId);
        policy.put("version", m.policyVersion);
        policy.put("hash", m.policyHash);
        parts.put("policy", Json.writeCanonical(policy));
        Map<String, Object> source = new LinkedHashMap<>();
        source.put("kind", Version.SOURCE_KIND);
        source.put("version", Version.SDK_VERSION);
        source.put("id", m.sourceId);
        parts.put("source", Json.writeCanonical(source));
        parts.put("ts", Json.quote(TS.format(Instant.ofEpochMilli(m.tsMs))));
        parts.put("latency_ms", String.valueOf(Math.max(0, m.latencyMs)));
        parts.put("dir", Json.quote(m.inbound ? "inbound" : "outbound"));
        if (m.netError != null) {
            parts.put("net_error", Json.quote(m.netError));
            parts.remove("resp");
        } else if (m.status >= 100 && m.status <= 599) {
            parts.put("status", String.valueOf(m.status));
        } else {
            return null;
        }
        if (m.traceId != null && HEX32.matcher(m.traceId).matches()) parts.put("trace_id", Json.quote(m.traceId));
        if (m.spanId != null && HEX16.matcher(m.spanId).matches()) parts.put("span_id", Json.quote(m.spanId));
        if (m.parentSpanId != null && HEX16.matcher(m.parentSpanId).matches()) parts.put("parent_span_id", Json.quote(m.parentSpanId));
        String s = Sanitizer.composeCanonical(parts);
        return s.length() > Sanitizer.MAX_EVENT_BYTES ? null : s;
    }

    /** An event waiting for export. */
    public record Queued(String json, long tsMs, String traceId, String spanId, String policyHash) {}

    private static void attr(StringBuilder sb, String key, String value) {
        sb.append("{\"key\":").append(Json.quote(key)).append(",\"value\":{\"stringValue\":").append(Json.quote(value)).append("}}");
    }

    /** OTLP/HTTP JSON body for a batch of events. */
    public static String otlpBody(List<Queued> events, String serviceName, String sourceId, long nowMs) {
        String observed = Long.toString(nowMs) + "000000";
        StringBuilder sb = new StringBuilder(events.size() * 512 + 512);
        sb.append("{\"resourceLogs\":[{\"resource\":{\"attributes\":[");
        attr(sb, "service.name", serviceName);
        sb.append(',');
        attr(sb, "tt.source.kind", Version.SOURCE_KIND);
        sb.append(',');
        attr(sb, "tt.source.version", Version.SDK_VERSION);
        sb.append(',');
        attr(sb, "tt.source.id", sourceId);
        sb.append("]},\"scopeLogs\":[{\"scope\":{\"name\":\"traffic-twin\",\"version\":").append(Json.quote(Version.SDK_VERSION)).append("},\"logRecords\":[");
        boolean first = true;
        for (Queued e : events) {
            if (!first) sb.append(',');
            first = false;
            sb.append("{\"timeUnixNano\":\"").append(e.tsMs()).append("000000\",\"observedTimeUnixNano\":\"").append(observed)
                .append("\",\"severityNumber\":9,\"severityText\":\"INFO\",\"eventName\":\"tt.http.exchange\"");
            if (e.traceId() != null && HEX32.matcher(e.traceId()).matches()) sb.append(",\"traceId\":\"").append(e.traceId()).append('"');
            if (e.spanId() != null && HEX16.matcher(e.spanId()).matches()) sb.append(",\"spanId\":\"").append(e.spanId()).append('"');
            sb.append(",\"attributes\":[");
            attr(sb, "tt.schema", "tt.http.exchange/v1");
            sb.append(',');
            attr(sb, "tt.policy.hash", e.policyHash());
            sb.append("],\"body\":{\"stringValue\":").append(Json.quote(e.json())).append("}}");
        }
        sb.append("]}]}]}");
        return sb.toString();
    }
}
