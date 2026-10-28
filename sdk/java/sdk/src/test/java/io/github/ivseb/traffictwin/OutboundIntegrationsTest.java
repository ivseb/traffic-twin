package io.github.ivseb.traffictwin;

import static io.github.ivseb.traffictwin.support.FakeCore.list;
import static io.github.ivseb.traffictwin.support.FakeCore.map;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.github.ivseb.traffictwin.capture.ExchangeContext;
import io.github.ivseb.traffictwin.integration.TrafficTwinClientInterceptor;
import io.github.ivseb.traffictwin.integration.TrafficTwinOkHttpInterceptor;
import io.github.ivseb.traffictwin.support.FakeCore;
import io.github.ivseb.traffictwin.support.Harness;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestTemplate;

/** The optional outbound integrations (HttpClient wrapper, Spring, OkHttp), net errors and propagation rules. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OutboundIntegrationsTest {
    Harness h;
    HttpServer internal;
    String internalUrl;
    final List<Map<String, List<String>>> internalHeaders = new CopyOnWriteArrayList<>();

    @BeforeAll
    void setUp() throws Exception {
        h = new Harness();
        internal = HttpServer.create(new InetSocketAddress(InetAddress.getByName("localhost"), 0), 0);
        internal.createContext("/", ex -> {
            internalHeaders.add(Map.copyOf(ex.getRequestHeaders()));
            ex.sendResponseHeaders(204, -1);
            ex.close();
        });
        internal.start();
        internalUrl = "http://localhost:" + internal.getAddress().getPort();
        Map<String, Object> p = h.policy();
        ((Map<String, Object>) p.get("sampling")).put("propagate_to", list("localhost:" + internal.getAddress().getPort()));
        h.start(p, true);
    }

    @AfterAll
    void tearDown() throws Exception {
        internal.stop(0);
        h.close();
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) {
        return (Map<String, Object>) o;
    }

    /** Waits until the exporter has delivered everything of the previous test (no new event for 400 ms). */
    @org.junit.jupiter.api.BeforeEach
    void quiesce() throws Exception {
        int n = -1;
        while (n != h.core.events.size()) {
            n = h.core.events.size();
            Thread.sleep(400);
        }
    }

    Map<String, Object> awaitEvent(int before) throws Exception {
        assertTrue(h.waitEvents(before + 1), "event arrived");
        return m(h.core.events.get(before));
    }

    @Test
    void springRestTemplateInterceptorCapturesWithoutChangingTheCall() throws Exception {
        int before = h.core.events.size();
        RestTemplate rt = new RestTemplate();
        rt.getInterceptors().add(new TrafficTwinClientInterceptor());
        HttpHeaders hd = new HttpHeaders();
        hd.set("content-type", "application/json");
        String out = rt.postForObject(h.carrierUrl + "/v1/shipments", new HttpEntity<>("{\"orderId\":\"ORD-2026-000184\"}", hd), String.class);
        assertEquals("{\"shipmentId\":\"SHP-5521\",\"status\":\"BOOKED\"}", out, "the application gets the real response");
        Map<String, Object> ev = awaitEvent(before);
        assertEquals("outbound", ev.get("dir"));
        assertEquals("carrier", ev.get("service"));
        assertEquals("POST /v1/shipments", ev.get("op"));
        assertTrue(((String) m(m(m(ev.get("req")).get("body"))).get("orderId")).startsWith("tk1:k1:"));
        assertTrue(m(ev.get("resp")).get("body") instanceof Map, h.core.eventStrings.get(before));
        assertEquals("keep:BOOKED", m(m(ev.get("resp")).get("body")).get("status"));
        assertFalse(h.core.eventStrings.get(before).contains("ORD-2026"));
    }

    @Test
    void okHttpInterceptorTeesTheResponseAsTheAppReadsIt() throws Exception {
        int before = h.core.events.size();
        OkHttpClient c = new OkHttpClient.Builder().addInterceptor(new TrafficTwinOkHttpInterceptor()).build();
        Request post = new Request.Builder().url(h.carrierUrl + "/v1/shipments")
            .post(RequestBody.create("{\"orderId\":\"ORD-2026-000184\"}", MediaType.get("application/json"))).build();
        try (Response r = c.newCall(post).execute()) {
            assertEquals("{\"shipmentId\":\"SHP-5521\",\"status\":\"BOOKED\"}", r.body().string());
        }
        Map<String, Object> ev = awaitEvent(before);
        assertEquals("POST /v1/shipments", ev.get("op"));
        assertTrue(((String) m(m(ev.get("req")).get("body")).get("orderId")).startsWith("tk1:k1:"));
        assertEquals("keep:BOOKED", m(m(ev.get("resp")).get("body")).get("status"));
        assertTrue(((String) ((List<?>) m(m(ev.get("req")).get("headers")).get("content-type")).get(0)).startsWith("keep:application/json"));
    }

    @Test
    void networkErrorsBecomeEventsWithoutAResponse() throws Exception {
        int before = h.core.events.size();
        int closed;
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            closed = s.getLocalPort();
        }
        try {
            h.wrapped.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + closed + "/v1/x")).GET().build(), HttpResponse.BodyHandlers.ofString());
            throw new AssertionError("expected a connection error");
        } catch (java.io.IOException expected) {
            // the application sees the exception, unchanged
        }
        Map<String, Object> ev = awaitEvent(before);
        assertEquals("refused", ev.get("net_error"));
        assertFalse(ev.containsKey("resp"));
        assertFalse(ev.containsKey("status"));
        assertEquals("host:ip:private:" + closed, ev.get("service"), "spec v1.5: a host not in the policy leaves as a pattern");
    }

    @Test
    void ipv6LiteralAndFinalDotReachTheSanitizerAsTheClientSeesThem() throws Exception {
        int closed;
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            closed = s.getLocalPort();
        }
        int before = h.core.events.size();
        try {
            h.wrapped.send(HttpRequest.newBuilder(URI.create("http://[::1]:" + closed + "/v1/x")).GET().build(), HttpResponse.BodyHandlers.ofString());
        } catch (java.io.IOException expected) {
            // whatever the network says; the event is what matters
        }
        assertEquals("host:ip:private:" + closed, awaitEvent(before).get("service"));
        quiesce();
        before = h.core.events.size();
        try {
            h.wrapped.send(HttpRequest.newBuilder(URI.create("http://localhost.:" + closed + "/v1/x")).GET().build(), HttpResponse.BodyHandlers.ofString());
        } catch (java.io.IOException expected) {
            // idem
        }
        assertEquals("host:localhost:" + closed, awaitEvent(before).get("service"), "the final dot is dropped by the sanitizer, not by the integration");
    }

    @Test
    void anUnsampledInboundExchangeMakesItsOutboundCallsInvisible() throws Exception {
        int before = h.core.events.size();
        ExchangeContext.set(new ExchangeContext(false, ExchangeContext.newTraceId(), true, ExchangeContext.newSpanId()));
        try {
            h.wrapped.send(HttpRequest.newBuilder(URI.create(h.carrierUrl + "/v1/shipments?orderId=ORD-1")).GET().build(), HttpResponse.BodyHandlers.ofString());
        } finally {
            ExchangeContext.set(null);
        }
        Thread.sleep(500);
        assertEquals(before, h.core.events.size());
    }

    @Test
    void sampledDecisionIsPropagatedAsBaggageOnlyToListedInternalHostsNeverToPolicyBases() throws Exception {
        ExchangeContext.set(new ExchangeContext(true, ExchangeContext.newTraceId(), true, ExchangeContext.newSpanId()));
        try {
            h.wrapped.send(HttpRequest.newBuilder(URI.create(internalUrl + "/x")).header("baggage", "userId=alice").GET().build(),
                HttpResponse.BodyHandlers.discarding());
            h.wrapped.send(HttpRequest.newBuilder(URI.create(h.carrierUrl + "/v1/shipments?orderId=ORD-1")).GET().build(), HttpResponse.BodyHandlers.discarding());
        } finally {
            ExchangeContext.set(null);
        }
        assertEquals(1, internalHeaders.size());
        List<String> bag = internalHeaders.get(0).get("Baggage");
        assertEquals(List.of("userId=alice,tt.s=1"), bag, "existing members untouched, tt.s added");
        for (Harness.Seen s : h.carrierSeen) {
            assertFalse(s.headers().keySet().stream().anyMatch(k -> k.equalsIgnoreCase("baggage")), "never toward an external service");
        }
    }

    @Test
    void theWrapperIsTransparentForAsyncCalls() throws Exception {
        int before = h.core.events.size();
        HttpResponse<String> r = h.wrapped.sendAsync(HttpRequest.newBuilder(URI.create(h.carrierUrl + "/v1/shipments?orderId=ORD-9")).GET().build(),
            HttpResponse.BodyHandlers.ofString()).get();
        assertEquals(201, r.statusCode());
        assertTrue(r.body().contains("SHP-5521"));
        Map<String, Object> ev = awaitEvent(before);
        assertEquals("GET /v1/shipments", ev.get("op"));
        assertNotNull(m(ev.get("req")).get("query"));
        assertNull(ev.get("net_error"));
    }
}
