package io.github.ivseb.traffictwin.capture;

import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Exchange context (event.md 1.1, sanitizer.md 12, ARCHITECTURE 3.2). A thread-local binds the
 * outbound calls made while serving an inbound request to that request: same trace id,
 * inherited sampling decision. W3C {@code traceparent} is read from the inbound request; this
 * class never injects it.
 */
public final class ExchangeContext {
    public final boolean sampled;
    public volatile String traceId;
    /** True when the trace id came from the request ({@code traceparent}) or from OpenTelemetry. */
    public volatile boolean traceKnown;
    public final String spanId;
    /** Framework route hint set by integrations running on the request thread (JAX-RS filter). */
    public volatile String framework;
    public volatile String frameworkRoute;

    public ExchangeContext(boolean sampled, String traceId, boolean traceKnown, String spanId) {
        this.sampled = sampled;
        this.traceId = traceId;
        this.traceKnown = traceKnown;
        this.spanId = spanId;
    }

    private static final ThreadLocal<ExchangeContext> CURRENT = new ThreadLocal<>();

    public static ExchangeContext current() {
        return CURRENT.get();
    }

    public static void set(ExchangeContext c) {
        if (c == null) CURRENT.remove();
        else CURRENT.set(c);
    }

    // --- ids ---------------------------------------------------------------------------

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private static String randomHex(int bytes) {
        ThreadLocalRandom r = ThreadLocalRandom.current();
        for (;;) {
            char[] c = new char[bytes * 2];
            boolean nonZero = false;
            for (int i = 0; i < bytes; i++) {
                int b = r.nextInt(256);
                c[2 * i] = HEX[b >> 4];
                c[2 * i + 1] = HEX[b & 15];
                if (b != 0) nonZero = true;
            }
            if (nonZero) return new String(c);
        }
    }

    public static String newTraceId() {
        return randomHex(16);
    }

    public static String newSpanId() {
        return randomHex(8);
    }

    // --- W3C trace context -----------------------------------------------------------------

    private static final Pattern TRACEPARENT = Pattern.compile("([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(-.*)?");

    /** Ids from a traceparent value, as {traceId, spanId}; null if invalid. */
    public static String[] parseTraceparent(String v) {
        if (v == null) return null;
        Matcher m = TRACEPARENT.matcher(v.trim());
        if (!m.matches()) return null;
        if (m.group(1).equals("ff") || (m.group(1).equals("00") && m.group(5) != null)) return null;
        if (m.group(2).matches("0+") || m.group(3).matches("0+")) return null;
        return new String[] {m.group(2), m.group(3)};
    }

    /** Adds {@code tt.s} to a baggage header value without touching the other members. */
    public static String withTtS(String existing, boolean sampled) {
        String member = "tt.s=" + (sampled ? "1" : "0");
        if (existing == null || existing.isBlank()) return member;
        return existing + "," + member;
    }
}
