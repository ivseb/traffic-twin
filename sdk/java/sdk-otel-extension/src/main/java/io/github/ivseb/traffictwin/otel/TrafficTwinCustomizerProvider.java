package io.github.ivseb.traffictwin.otel;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.context.Context;
import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizer;
import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizerProvider;
import io.opentelemetry.sdk.trace.ReadWriteSpan;
import io.opentelemetry.sdk.trace.ReadableSpan;
import io.opentelemetry.sdk.trace.SpanProcessor;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Extension of the OpenTelemetry Java agent for traffic-twin.
 *
 * <pre>
 * java -javaagent:opentelemetry-javaagent.jar \
 *      -Dotel.javaagent.extensions=sdk-otel-extension-0.1.1.jar \
 *      -jar app.jar
 * </pre>
 *
 * <p>What it does, and nothing else: it adds a read-only {@link SpanProcessor} to the agent's tracer
 * provider that remembers, for each live SERVER span, how to read its {@code http.route} (the route
 * template the agent's own instrumentation computed). The traffic-twin servlet filter, which runs in
 * the application's class loader, asks for it by span id when it needs the {@code framework_route}
 * of an exchange (sanitizer.md 3.4).
 *
 * <p>What it never does: set {@code GlobalOpenTelemetry} or any other global, register a
 * propagator, add or change a span, attribute, link or event, export anything, or open a connection.
 * It has no dependency on the traffic-twin SDK: the two sides meet through a named
 * {@code java.util.logging.Logger} (a JDK object visible to every class loader), see
 * {@code OtelRouteHints} in the SDK. {@code TT_DISABLED=1} or {@code -Dtt.otel.hints=false} turn the
 * hook off.
 *
 * <p>The agent rewrites references to {@code java.util.logging.Logger} in extension code to its own
 * restricted {@code PatchLogger}, so the rendezvous logger is reached by reflection, with class names
 * assembled at run time so that no relocation touches them.
 */
public final class TrafficTwinCustomizerProvider implements AutoConfigurationCustomizerProvider {
    /** Same string as {@code OtelRouteHints.LOGGER} in the SDK. */
    static final String LOGGER = "io.github.ivseb.traffictwin.otel.route-hints";

    /** Lookup key meaning "the server span of the calling thread". */
    static final String CURRENT = "@current";

    private static final ThreadLocal<ReadWriteSpan> CURRENT_SERVER = new ThreadLocal<>();
    private static final int MAX_LIVE = 10_000;
    private static final AttributeKey<String> HTTP_ROUTE = AttributeKey.stringKey("http.route");
    private static final Map<String, Supplier<String>> LIVE = new ConcurrentHashMap<>();
    // Strong reference: LogManager keeps loggers weakly.
    private static volatile Object rendezvous;

    @Override
    public void customize(AutoConfigurationCustomizer c) {
        if (disabled()) return;
        install();
        c.addTracerProviderCustomizer((builder, config) -> builder.addSpanProcessor(new RouteProcessor()));
    }

    private static boolean disabled() {
        String d = System.getenv("TT_DISABLED");
        return "1".equals(d) || "true".equalsIgnoreCase(d) || "false".equalsIgnoreCase(System.getProperty("tt.otel.hints"));
    }

    /** Answers {@code (spanId, String[1])} lookups through the filter of the rendezvous logger. */
    static synchronized void install() {
        if (rendezvous != null) return;
        try {
            String pkg = "java.util." + "logging.";
            Class<?> loggerClass = Class.forName(pkg + "Logger");
            Class<?> filterClass = Class.forName(pkg + "Filter");
            Class<?> recordClass = Class.forName(pkg + "LogRecord");
            Method getParameters = recordClass.getMethod("getParameters");
            Object logger = loggerClass.getMethod("getLogger", String.class).invoke(null, LOGGER);
            loggerClass.getMethod("setUseParentHandlers", boolean.class).invoke(logger, false);
            Object filter = Proxy.newProxyInstance(filterClass.getClassLoader(), new Class<?>[] {filterClass}, (proxy, method, args) -> {
                if (method.getName().equals("isLoggable") && args != null && args.length == 1) {
                    Object[] p = (Object[]) getParameters.invoke(args[0]);
                    if (p != null && p.length == 2 && p[0] instanceof String key && p[1] instanceof String[] out) {
                        if (key.equals(CURRENT)) {
                            // "traceId/spanId" of the SERVER span this thread is serving, for applications
                            // that do not have the OpenTelemetry API on their class path.
                            ReadWriteSpan cur = CURRENT_SERVER.get();
                            out[0] = cur == null ? null : cur.getSpanContext().getTraceId() + "/" + cur.getSpanContext().getSpanId();
                        } else {
                            Supplier<String> s = LIVE.get(key);
                            out[0] = s == null ? null : s.get();
                        }
                    }
                    return Boolean.FALSE; // never a log message
                }
                if (method.getName().equals("hashCode")) return System.identityHashCode(proxy);
                if (method.getName().equals("equals")) return proxy == args[0];
                return null;
            });
            loggerClass.getMethod("setFilter", filterClass).invoke(logger, filter);
            rendezvous = logger;
        } catch (ReflectiveOperationException | RuntimeException e) {
            // No rendezvous: the SDK simply finds no hint. Never affect the application or the agent.
        }
    }

    /** Read-only: observes SERVER spans, never touches them. */
    static final class RouteProcessor implements SpanProcessor {
        @Override
        public void onStart(Context parentContext, ReadWriteSpan span) {
            try {
                if (span.getKind() != SpanKind.SERVER) return;
                if (LIVE.size() >= MAX_LIVE) LIVE.clear(); // spans that never ended must not leak memory
                LIVE.put(span.getSpanContext().getSpanId(), () -> span.getAttribute(HTTP_ROUTE));
                CURRENT_SERVER.set(span);
            } catch (RuntimeException e) {
                // never affect the application
            }
        }

        @Override
        public boolean isStartRequired() {
            return true;
        }

        @Override
        public void onEnd(ReadableSpan span) {
            try {
                LIVE.remove(span.getSpanContext().getSpanId());
                ReadWriteSpan cur = CURRENT_SERVER.get();
                if (cur != null && cur.getSpanContext().getSpanId().equals(span.getSpanContext().getSpanId())) CURRENT_SERVER.remove();
            } catch (RuntimeException e) {
                // never affect the application
            }
        }

        @Override
        public boolean isEndRequired() {
            return true;
        }
    }
}
