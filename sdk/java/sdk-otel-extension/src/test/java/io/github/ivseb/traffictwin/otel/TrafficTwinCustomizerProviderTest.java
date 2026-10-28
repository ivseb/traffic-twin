package io.github.ivseb.traffictwin.otel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.ivseb.traffictwin.capture.OtelRouteHints;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizer;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.SdkTracerProviderBuilder;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.function.BiFunction;
import org.junit.jupiter.api.Test;

/** The extension's hook is read-only and shares the route template with the SDK side through the JDK-only rendezvous. */
class TrafficTwinCustomizerProviderTest {
    @SuppressWarnings({"unchecked", "rawtypes"})
    static SdkTracerProviderBuilder customize(SdkTracerProviderBuilder b) {
        BiFunction[] captured = new BiFunction[1];
        AutoConfigurationCustomizer fake = (AutoConfigurationCustomizer) Proxy.newProxyInstance(
            AutoConfigurationCustomizer.class.getClassLoader(), new Class<?>[] {AutoConfigurationCustomizer.class}, (p, m, a) -> {
                if (m.getName().equals("addTracerProviderCustomizer")) captured[0] = (BiFunction) a[0];
                return p;
            });
        new TrafficTwinCustomizerProvider().customize(fake);
        assertNotNull(captured[0], "the provider registers a tracer provider customizer");
        return (SdkTracerProviderBuilder) captured[0].apply(b, null);
    }

    @Test
    void theSdkSideReadsTheRouteOfALiveServerSpanAndSpansAreUntouched() throws Exception {
        assertNull(OtelRouteHints.lookup("0123456789abcdef"), "no hint for unknown spans");
        InMemorySpanExporter exporter = InMemorySpanExporter.create();
        SdkTracerProvider tp = customize(SdkTracerProvider.builder().addSpanProcessor(SimpleSpanProcessor.create(exporter))).build();
        Tracer tracer = OpenTelemetrySdk.builder().setTracerProvider(tp).build().getTracer("t");

        Span server = tracer.spanBuilder("GET").setSpanKind(SpanKind.SERVER).startSpan();
        Span client = tracer.spanBuilder("call").setSpanKind(SpanKind.CLIENT).setAttribute("http.route", "/not/a/server").startSpan();
        var cur = OtelRouteHints.current();
        assertNotNull(cur, "the thread is serving the server span (applications without the OpenTelemetry API jar rely on this)");
        assertEquals(server.getSpanContext().getTraceId(), cur.traceId());
        assertEquals(server.getSpanContext().getSpanId(), cur.spanId());
        try (Scope s = server.makeCurrent()) {
            assertNull(OtelRouteHints.lookup(server.getSpanContext().getSpanId()), "route not named yet");
            server.setAttribute("http.route", "/orders/{id}"); // what the agent's instrumentation does mid-request
            assertEquals("/orders/{id}", OtelRouteHints.lookup(server.getSpanContext().getSpanId()));
            assertNull(OtelRouteHints.lookup(client.getSpanContext().getSpanId()), "only server spans");
        }
        client.end();
        server.end();
        assertNull(OtelRouteHints.lookup(server.getSpanContext().getSpanId()), "forgotten when the span ends");
        assertNull(OtelRouteHints.current(), "no server span any more");

        List<SpanData> spans = exporter.getFinishedSpanItems();
        assertEquals(2, spans.size());
        SpanData sd = spans.stream().filter(x -> x.getKind() == SpanKind.SERVER).findFirst().orElseThrow();
        assertEquals(1, sd.getAttributes().size(), "no attribute was added to the span");
        assertEquals("/orders/{id}", sd.getAttributes().asMap().values().iterator().next());
        assertTrue(sd.getLinks().isEmpty() && sd.getEvents().isEmpty());
    }

    @Test
    void itNeverSetsGlobalOpenTelemetry() throws Exception {
        customize(SdkTracerProvider.builder());
        Field f = GlobalOpenTelemetry.class.getDeclaredField("globalOpenTelemetry");
        f.setAccessible(true);
        assertNull(f.get(null));
    }
}
