package io.github.ivseb.traffictwin.capture;

import java.util.logging.Filter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Reads the route template that the OpenTelemetry Java agent computed for a server span
 * ({@code http.route}), published by the {@code sdk-otel-extension} module.
 *
 * <p>The extension lives in the agent's class loader and the SDK in the application's, so they share
 * no class. They meet through a JDK object both can see: a named {@link Logger} whose
 * {@link Filter} answers lookups (the span id goes in, the route comes out through the record
 * parameters). Nothing is logged and no system property is touched. Without the extension, the
 * logger has no filter and {@link #lookup} returns null.
 */
public final class OtelRouteHints {
    private OtelRouteHints() {}

    /** Name of the rendezvous logger; the extension module uses the same string. */
    public static final String LOGGER = "io.github.ivseb.traffictwin.otel.route-hints";

    /** Ids of the server span the calling thread is serving, as the extension sees it; null without the extension. */
    public static OtelContext.Ids current() {
        String v = ask("@current");
        if (v == null) return null;
        int slash = v.indexOf('/');
        if (slash != 32 || v.length() != 32 + 1 + 16) return null;
        return new OtelContext.Ids(v.substring(0, 32), v.substring(33));
    }

    /** Route template of the live server span with this id, or null. Never throws. */
    public static String lookup(String spanId) {
        if (spanId == null || spanId.isEmpty()) return null;
        return ask(spanId);
    }

    private static volatile Filter cached;
    private static volatile long nextCheckNanos;

    /** The extension's filter; looked up at most every 5 s while it is absent, so apps without it pay nothing. */
    private static Filter filter() {
        Filter f = cached;
        if (f != null) return f;
        long now = System.nanoTime();
        if (now - nextCheckNanos < 0) return null;
        nextCheckNanos = now + 5_000_000_000L;
        f = Logger.getLogger(LOGGER).getFilter();
        cached = f;
        return f;
    }

    private static String ask(String key) {
        try {
            Filter f = filter();
            if (f == null) return null;
            String[] out = new String[1];
            LogRecord r = new LogRecord(Level.FINEST, "");
            r.setParameters(new Object[] {key, out});
            f.isLoggable(r);
            return out[0];
        } catch (RuntimeException e) {
            return null;
        }
    }
}
