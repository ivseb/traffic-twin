package io.github.ivseb.traffictwin.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.ivseb.traffictwin.support.Harness;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * Zero-code injection: the application (embedded Tomcat or Jetty, started with no traffic-twin code at
 * all) runs in a child JVM with {@code -javaagent:traffic-twin-agent.jar}; this JVM plays tt-core and
 * the carrier. Asserts the sanitized inbound and outbound events and that the application's traffic is
 * exactly what it was without the agent.
 */
class AgentIT {
    static final String ORDER = "{\"items\":[{\"sku\":\"TSHIRT-RED-M\",\"qty\":2}],\"email\":\"giulia.neri@example.com\"}";
    static final String ALL_CLIENTS = "jdk,spring,restclient,okhttp";

    static List<String> agent() {
        return List.of("-javaagent:" + ChildApp.AGENT);
    }

    /** Runs one order against the app and checks everything the agent must and must not do. */
    static void exerciseOrder(ChildApp app, Set<String> expectedClients) throws Exception {
        exerciseOrder(app, expectedClients, false);
    }

    static void exerciseOrder(ChildApp app, Set<String> expectedClients, boolean otelPresent) throws Exception {
        int outboundClients = expectedClients.size();
        app.awaitCapturing();
        int carrierBefore = app.carrierSeen.size();
        HttpResponse<String> r = app.post("/orders?promo=AUTUMN10", ORDER);

        // The application's own answer is untouched.
        assertEquals(201, r.statusCode());
        assertEquals("{\"id\":\"ORD-2026-000184\",\"status\":\"CREATED\",\"echo\":" + ORDER.length() + "}", r.body());

        assertTrue(app.core.waitFor(c -> orderEvents(app).size() >= 1 + outboundClients, 15_000),
            "events: " + app.core.events.size() + "\n" + String.join("\n", app.output));
        List<Map<String, Object>> evs = orderEvents(app);
        List<Map<String, Object>> in = evs.stream().filter(e -> e.get("dir").equals("inbound")).toList();
        List<Map<String, Object>> out = evs.stream().filter(e -> e.get("dir").equals("outbound")).toList();
        assertEquals(1, in.size(), evs.toString());
        assertEquals(outboundClients, out.size(), evs.toString());
        assertEquals("POST /orders", in.get(0).get("op"));
        assertEquals("shop-api", in.get(0).get("service"));
        for (Map<String, Object> o : out) {
            assertEquals("POST /v1/shipments", o.get("op"));
            assertEquals("carrier", o.get("service"));
            assertEquals(in.get(0).get("trace_id"), o.get("trace_id"), "outbound calls inherit the trace of the inbound exchange");
            assertEquals(in.get(0).get("span_id"), o.get("parent_span_id"));
        }

        // Nothing sensitive left the process.
        String all = app.core.eventStrings.stream().collect(Collectors.joining("\n"));
        for (String secret : new String[] {"giulia.neri", "TSHIRT-RED-M", "ORD-2026-000184", "carrier-api-key", "9f8e7d6c5b4a"}) {
            assertFalse(all.contains(secret), secret);
        }

        // The carrier saw the calls as the application made them: no injected traceparent, no baggage.
        List<ChildApp.Seen> seen = app.carrierSeen.subList(carrierBefore, app.carrierSeen.size());
        assertEquals(outboundClients, seen.size());
        for (ChildApp.Seen s : seen) {
            assertEquals(ChildAppShipment.BODY, s.body());
            assertFalse(s.headers().keySet().stream().anyMatch(k -> (!otelPresent && k.equalsIgnoreCase("traceparent")) || k.equalsIgnoreCase("baggage")), s.headers().toString());
        }
        Set<String> clients = seen.stream().map(s -> s.headers().entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase("x-client"))
            .map(e -> e.getValue().get(0)).findFirst().orElse("?")).collect(Collectors.toSet());
        assertEquals(expectedClients, clients);
    }

    /** The inbound "POST /orders" event and every outbound event of its trace (the warm-up requests are left out). */
    static List<Map<String, Object>> orderEvents(ChildApp app) {
        List<Map<String, Object>> all = app.events();
        String trace = all.stream().filter(e -> "inbound".equals(e.get("dir")) && "POST /orders".equals(e.get("op")))
            .map(e -> (String) e.get("trace_id")).findFirst().orElse(null);
        if (trace == null) return List.of();
        return all.stream().filter(e -> trace.equals(e.get("trace_id"))).toList();
    }

    /** Same constant as the app's shipment body. */
    static final class ChildAppShipment {
        static final String BODY = "{\"orderId\":\"ORD-2026-000184\",\"email\":\"giulia.neri@example.com\"}";
    }

    @Test
    void tomcatJakarta_servletFilterAndAllOutboundClients() throws Exception {
        try (ChildApp app = new ChildApp()) {
            app.start("tomcat", agent(), app.ttEnv(), ALL_CLIENTS);
            exerciseOrder(app, Set.of("jdk", "spring", "restclient", "okhttp"));
            assertTrue(app.output.stream().anyMatch(l -> l.contains("hooked org/apache/catalina/core/StandardContext")), String.join("\n", app.output));
            assertTrue(app.output.stream().anyMatch(l -> l.contains("hooked jdk/internal/net/http/HttpClientFacade")), String.join("\n", app.output));
        }
    }

    @Test
    void jetty11_servletFilterAndAllOutboundClients() throws Exception {
        try (ChildApp app = new ChildApp()) {
            app.start("jetty", agent(), app.ttEnv(), ALL_CLIENTS);
            exerciseOrder(app, Set.of("jdk", "spring", "restclient", "okhttp"));
        }
    }

    @Test
    void tomcat9Javax_servletFilterAndJdkClient() throws Exception {
        try (ChildApp app = new ChildApp()) {
            app.start("tomcat9", agent(), app.ttEnv(), "jdk");
            exerciseOrder(app, Set.of("jdk"));
        }
    }

    /**
     * RT3-FW-1: a parser that stops at the closing brace (Spring's @RequestBody) never reads the end of the
     * stream; the body is still captured, with a Content-Length and chunked.
     */
    @Test
    void bodiesReadByAStreamingParserWithoutReachingTheEndAreCaptured() throws Exception {
        for (String flavour : new String[] {"tomcat", "tomcat9", "jetty"}) {
            for (boolean chunked : new boolean[] {false, true}) {
                try (ChildApp app = new ChildApp()) {
                    app.start(flavour, agent(), app.ttEnv(), "jdk");
                    app.awaitCapturing();
                    String what = flavour + (chunked ? " chunked" : " content-length");
                    java.net.http.HttpRequest.BodyPublisher body = java.net.http.HttpRequest.BodyPublishers.ofString(ORDER);
                    if (chunked) body = java.net.http.HttpRequest.BodyPublishers.fromPublisher(body); // unknown length
                    HttpResponse<String> r = app.http.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create("http://127.0.0.1:" + app.port + "/orders?read=partial"))
                        .header("content-type", "application/json").POST(body).build(), HttpResponse.BodyHandlers.ofString());
                    assertEquals(201, r.statusCode(), what);
                    assertTrue(app.core.waitFor(c -> app.events().stream().anyMatch(e -> "POST /orders".equals(e.get("op"))), 15_000), what);
                    Map<String, Object> in = app.events().stream().filter(e -> "POST /orders".equals(e.get("op"))).findFirst().orElseThrow();
                    @SuppressWarnings("unchecked")
                    Map<String, Object> req = (Map<String, Object>) in.get("req");
                    assertTrue(req.get("body") instanceof Map, what + ": body captured, was " + req.get("body") + " size " + req.get("size"));
                }
            }
        }
    }

    @Test
    void inertWithoutEnrollUrlOrWhenDisabled() throws Exception {
        for (String mode : new String[] {"no-url", "disabled"}) {
            try (ChildApp app = new ChildApp()) {
                Map<String, String> env = app.ttEnv();
                if (mode.equals("no-url")) env.remove("TT_ENROLL_URL");
                else env.put("TT_DISABLED", "1");
                app.start("jetty", agent(), env, "jdk");
                HttpResponse<String> r = app.post("/orders", ORDER);
                assertEquals(201, r.statusCode(), mode);
                Thread.sleep(1000);
                assertEquals(0, app.core.enrollments.size(), mode);
                assertTrue(app.core.events.isEmpty(), mode);
                assertFalse(app.output.stream().anyMatch(l -> l.contains("hooked")), mode + String.join("\n", app.output));
            }
        }
    }

    @Test
    void agentJarHasNoExternalDependencyAndNeverTouchesOpenTelemetryGlobals() throws Exception {
        try (var jar = new java.util.jar.JarFile(ChildApp.AGENT)) {
            var entries = jar.entries();
            while (entries.hasMoreElements()) {
                var e = entries.nextElement();
                String n = e.getName();
                // Only a handful of JDK-only classes are loadable by name; the SDK itself is data in the jar.
                assertTrue(e.isDirectory() || n.startsWith("META-INF/")
                    || (n.startsWith("tt/core/io/github/ivseb/traffictwin/") && n.endsWith(".classdata"))
                    || (n.startsWith("tt/ext/io/github/ivseb/traffictwin/") && n.endsWith(".classdata"))
                    || (n.startsWith("io/github/ivseb/traffictwin/agent/") && n.endsWith(".class")), "unexpected entry " + n);
                if (n.endsWith(".class") || n.endsWith(".classdata")) {
                    byte[] b = jar.getInputStream(e).readAllBytes();
                    String s = new String(b, java.nio.charset.StandardCharsets.ISO_8859_1);
                    assertFalse(s.contains("GlobalOpenTelemetry"), n);
                    assertFalse(s.contains("setDefault"), n); // SSLContext/Authenticator/ProxySelector/CookieHandler defaults
                    assertFalse(s.contains("org/objectweb/asm"), n);
                }
            }
            var m = jar.getManifest().getMainAttributes();
            assertNotNull(m.getValue("Premain-Class"));
            assertNotNull(m.getValue("Agent-Class"));
        }
    }
}
