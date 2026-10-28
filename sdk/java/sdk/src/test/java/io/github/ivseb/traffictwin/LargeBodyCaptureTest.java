package io.github.ivseb.traffictwin;

import static io.github.ivseb.traffictwin.support.FakeCore.map;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.ivseb.traffictwin.support.Harness;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

/**
 * Spec v1.19 (sanitizer.md 22.5): with {@code bodies.max_large_body_bytes} the capture layer keeps
 * {@code max(max_body_bytes, max_large_body_bytes) + 1} bytes, so an XML body larger than
 * {@code max_body_bytes} is still analysed (servlet filter in, {@code TrafficTwinHttpClient} out).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class LargeBodyCaptureTest {
    Harness h;

    @BeforeAll
    void setUp() throws Exception {
        h = new Harness();
        Map<String, Object> p = h.policy();
        p.put("limits", map("max_body_bytes", 256L, "max_depth", 32L, "max_array", 32L, "max_keys", 256L, "keep_max_bytes", 64L));
        p.put("bodies", map("xml", true, "multipart", false, "docs", false, "max_large_body_bytes", 8192L, "large_array", 3L, "large_nested_array", 1L));
        h.start(p, true);
    }

    @AfterAll
    void tearDown() throws Exception {
        if (h != null) h.close();
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) {
        return (Map<String, Object>) o;
    }

    static String xml() {
        StringBuilder sb = new StringBuilder("<?xml version=\"1.0\"?><list xmlns=\"urn:shop:v1\">");
        for (int i = 0; i < 20; i++) sb.append("<item code=\"SKU-").append(i).append("\"><name>Invented item ").append(i).append("</name></item>");
        return sb.append("</list>").toString();
    }

    static void assertLargeXml(Map<String, Object> side) {
        assertEquals("xml", side.get("fmt"));
        assertEquals("lmax", side.get("size"));
        List<?> items = (List<?>) m(m(side.get("body")).get("list")).get("item");
        assertEquals(4, items.size(), "large_array = 3 items + trunc marker: " + items);
        assertEquals("trunc:n:l32", items.get(3));
        assertEquals(Map.of("@code", "drop:str:l8", "name", "drop:str:l32"), items.get(0));
        assertEquals(Map.of("$.list", "ns:urn:shop:v1"), side.get("xmlns"));
    }

    @Test
    void inboundLargeXmlIsAnalysed() throws Exception {
        String body = xml();
        assertTrue(body.length() > 256 && body.length() < 8192);
        int before = h.core.events.size();
        HttpRequest rq = HttpRequest.newBuilder(URI.create(h.appUrl("/echo"))).header("content-type", "application/xml")
            .POST(HttpRequest.BodyPublishers.ofString(body)).build();
        HttpResponse<String> r = h.plain.send(rq, HttpResponse.BodyHandlers.ofString());
        assertEquals(body, r.body(), "the app sees the body unchanged");
        assertTrue(h.waitEvents(before + 1));
        Map<String, Object> ev = m(h.core.events.get(before));
        assertLargeXml(m(ev.get("req")));
        assertFalse(h.core.eventStrings.get(before).contains("Invented"));
    }

    @Test
    void outboundLargeXmlIsAnalysed() throws Exception {
        int before = h.core.events.size();
        HttpRequest rq = HttpRequest.newBuilder(URI.create(h.carrierUrl + "/v1/shipments")).header("content-type", "text/xml")
            .header("soapaction", "\"urn:shop#CreateShipment\"").POST(HttpRequest.BodyPublishers.ofString(xml())).build();
        h.wrapped.send(rq, HttpResponse.BodyHandlers.ofString());
        assertTrue(h.waitEvents(before + 1));
        Map<String, Object> ev = h.core.events.subList(before, h.core.events.size()).stream().map(LargeBodyCaptureTest::m)
            .filter(e -> "carrier".equals(e.get("service"))).findFirst().orElseThrow();
        assertLargeXml(m(ev.get("req")));
        assertEquals("CreateShipment", m(ev.get("req")).get("soap_action"));
    }
}
