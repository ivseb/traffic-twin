package io.github.ivseb.traffictwin.capture;

import java.lang.reflect.Method;
import java.util.regex.Pattern;

/**
 * Reads the active OpenTelemetry span context, if the application has OpenTelemetry (the API
 * jar, or the Java agent which provides it). Everything is reflective and read-only: this class
 * never registers a provider, propagator or context storage and never touches
 * {@code GlobalOpenTelemetry}. It calls only {@code Span.current().getSpanContext()}.
 */
public final class OtelContext {
    private OtelContext() {}

    /** Active span ids; spanId is empty when unknown. */
    public record Ids(String traceId, String spanId) {}

    private static final Pattern HEX32 = Pattern.compile("[0-9a-f]{32}");
    private static final Pattern HEX16 = Pattern.compile("[0-9a-f]{16}");
    private static volatile boolean resolved = false;
    private static Method current;
    private static Method spanContext;
    private static Method traceId;
    private static Method spanId;
    private static Method isValid;

    private static synchronized void resolve() {
        if (resolved) return;
        try {
            Class<?> span = load("io.opentelemetry.api.trace.Span");
            Class<?> sc = load("io.opentelemetry.api.trace.SpanContext");
            if (span != null && sc != null) {
                current = span.getMethod("current");
                spanContext = span.getMethod("getSpanContext");
                traceId = sc.getMethod("getTraceId");
                spanId = sc.getMethod("getSpanId");
                isValid = sc.getMethod("isValid");
            }
        } catch (ReflectiveOperationException | LinkageError e) {
            current = null;
        }
        resolved = true;
    }

    private static Class<?> load(String name) {
        ClassLoader[] cls = {Thread.currentThread().getContextClassLoader(), OtelContext.class.getClassLoader(), ClassLoader.getSystemClassLoader()};
        for (ClassLoader cl : cls) {
            if (cl == null) continue;
            try {
                return Class.forName(name, false, cl);
            } catch (ClassNotFoundException | LinkageError e) {
                // next loader
            }
        }
        return null;
    }

    /** True when the OpenTelemetry API is visible to the SDK. */
    public static boolean available() {
        resolve();
        return current != null;
    }

    /** Active valid span context of the calling thread, or null. Never throws. */
    public static Ids active() {
        if (!resolved) resolve();
        // No OpenTelemetry API visible (the agent only bridges an API jar that the application brings):
        // ask the agent extension, if present, for the server span of this thread.
        if (current == null) return OtelRouteHints.current();
        try {
            Object span = current.invoke(null);
            Object sc = spanContext.invoke(span);
            if (!Boolean.TRUE.equals(isValid.invoke(sc))) return null;
            String t = (String) traceId.invoke(sc);
            String s = (String) spanId.invoke(sc);
            if (t == null || !HEX32.matcher(t).matches() || t.matches("0+")) return null;
            return new Ids(t, s != null && HEX16.matcher(s).matches() ? s : "");
        } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
            return null;
        }
    }
}
