package io.github.ivseb.traffictwin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.ivseb.traffictwin.capture.OtelContext;
import io.github.ivseb.traffictwin.support.Harness;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * ARCHITECTURE 3.2: an app with OpenTelemetry keeps exporting exactly the same spans when the
 * traffic-twin agent runs, and the SDK only reads (never replaces) its context.
 */
class OtelCoexistenceTest {
    /** A private SDK (never registered globally), like an application that wires OpenTelemetry itself. */
    static final class App {
        final InMemorySpanExporter exporter = InMemorySpanExporter.create();
        final SdkTracerProvider provider = SdkTracerProvider.builder().addSpanProcessor(SimpleSpanProcessor.create(exporter)).build();
        final OpenTelemetry otel = OpenTelemetrySdk.builder().setTracerProvider(provider).build();
        final Tracer tracer = otel.getTracer("test-app");

        /** Stands for the APM server instrumentation: a SERVER span around the rest of the chain. */
        Filter serverSpanFilter() {
            return new Filter() {
                @Override
                public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
                    HttpServletRequest r = (HttpServletRequest) req;
                    Span span = tracer.spanBuilder(r.getMethod() + " " + r.getRequestURI()).setSpanKind(SpanKind.SERVER)
                        .setAttribute("http.route", r.getRequestURI()).startSpan();
                    try (Scope ignored = span.makeCurrent()) {
                        chain.doFilter(req, res);
                    } finally {
                        span.end();
                    }
                }
            };
        }
    }

    HttpServlet workServlet(App app, Harness h) {
        return new HttpServlet() {
            @Override
            protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
                Span internal = app.tracer.spanBuilder("work").startSpan();
                try (Scope s = internal.makeCurrent()) {
                    Span client = app.tracer.spanBuilder("GET carrier").setSpanKind(SpanKind.CLIENT).setAttribute("peer", "carrier").startSpan();
                    try (Scope cs = client.makeCurrent()) {
                        h.wrapped.send(HttpRequest.newBuilder(URI.create(h.carrierUrl + "/v1/shipments?orderId=ORD-2026-000184")).GET().build(),
                            HttpResponse.BodyHandlers.ofString());
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        client.end();
                    }
                } finally {
                    internal.end();
                }
                res.setContentType("application/json");
                res.getWriter().write("{\"ok\":true}");
            }
        };
    }

    record Shape(String name, SpanKind kind, Map<String, String> attributes, String parent) {}

    static List<Shape> shapes(List<SpanData> spans) {
        Map<String, String> names = new HashMap<>();
        for (SpanData s : spans) names.put(s.getSpanId(), s.getName() + "/" + s.getKind());
        List<Shape> out = new ArrayList<>();
        for (SpanData s : spans) {
            Map<String, String> attrs = new java.util.TreeMap<>();
            s.getAttributes().forEach((k, v) -> attrs.put(k.getKey(), String.valueOf(v)));
            out.add(new Shape(s.getName(), s.getKind(), attrs, names.get(s.getParentSpanId())));
        }
        out.sort(java.util.Comparator.comparing(Shape::toString));
        return out;
    }

    List<SpanData> run(boolean withAgent, List<Map<String, Object>> eventsOut) throws Exception {
        App app = new App();
        try (Harness h = new Harness()) {
            h.preFilters.add(app.serverSpanFilter());
            h.extraServlets.put("/work", workServlet(app, h));
            if (withAgent) h.start(h.policy(), true);
            else h.startAppOnly();
            for (int i = 0; i < 3; i++) {
                HttpResponse<String> r = h.call("GET", "/work", Map.of(), null);
                assertEquals(200, r.statusCode());
                assertEquals("{\"ok\":true}", r.body());
            }
            if (withAgent) {
                assertTrue(h.waitEvents(6), "events exported: " + h.core.events.size());
                for (Object e : h.core.events) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> ev = (Map<String, Object>) e;
                    eventsOut.add(ev);
                }
            }
            List<SpanData> spans = new ArrayList<>(app.exporter.getFinishedSpanItems());
            assertEquals(9, spans.size(), "3 requests x (server, internal, client)");
            return spans;
        }
    }

    @Test
    void appSpansAreUnchangedAndEventsReuseTheAppTrace() throws Exception {
        assertTrue(OtelContext.available(), "the OpenTelemetry API is visible to the SDK");
        List<SpanData> without = run(false, new ArrayList<>());
        List<Map<String, Object>> events = new ArrayList<>();
        List<SpanData> with = run(true, events);

        assertEquals(shapes(without), shapes(with), "same span names, kinds, attributes and structure");

        // The agent read the active context: events share the app's own trace and server span ids.
        Set<String> traces = new HashSet<>();
        Set<String> serverSpans = new HashSet<>();
        for (SpanData s : with) {
            traces.add(s.getTraceId());
            if (s.getKind() == SpanKind.SERVER) serverSpans.add(s.getSpanId());
        }
        int inbound = 0;
        int outbound = 0;
        for (Map<String, Object> e : events) {
            assertTrue(traces.contains(e.get("trace_id")), "event on an app trace: " + e.get("trace_id"));
            if (e.get("dir").equals("inbound")) {
                inbound++;
                assertTrue(serverSpans.contains(e.get("span_id")), "inbound span_id is the app's server span");
            } else {
                outbound++;
                assertTrue(serverSpans.contains(e.get("parent_span_id")), "outbound parent is the inbound span");
            }
        }
        assertEquals(3, inbound);
        assertEquals(3, outbound);
    }

    @Test
    void theSdkNeverRegistersGlobalOpenTelemetry() throws Exception {
        // Reading Span.current() must not create or register anything global.
        Span.current();
        OtelContext.active();
        Field f = GlobalOpenTelemetry.class.getDeclaredField("globalOpenTelemetry");
        f.setAccessible(true);
        assertNull(f.get(null), "no GlobalOpenTelemetry was set by anyone");
    }
}
