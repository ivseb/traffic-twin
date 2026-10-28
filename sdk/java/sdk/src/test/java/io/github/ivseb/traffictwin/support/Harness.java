package io.github.ivseb.traffictwin.support;

import static io.github.ivseb.traffictwin.support.FakeCore.list;
import static io.github.ivseb.traffictwin.support.FakeCore.map;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.ivseb.traffictwin.Config;
import io.github.ivseb.traffictwin.TrafficTwin;
import io.github.ivseb.traffictwin.integration.TrafficTwinHttpClient;
import io.github.ivseb.traffictwin.servlet.TrafficTwinFilter;
import jakarta.servlet.AsyncContext;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Cookie;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

/** A shop app on Jetty, a fake carrier, a fake tt-core and a running agent: the end-to-end rig. */
public final class Harness implements AutoCloseable {
    public static final String HMAC_KEY = "k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    private static TestPki sharedPki;

    public static synchronized TestPki pki() throws Exception {
        if (sharedPki == null) sharedPki = new TestPki();
        return sharedPki;
    }

    /** A request seen by the fake carrier. */
    public record Seen(String method, String uri, Map<String, List<String>> headers, String body) {}

    public final HttpServer carrier;
    public final String carrierUrl;
    public final List<Seen> carrierSeen = new CopyOnWriteArrayList<>();
    public FakeCore core;
    public Server jetty;
    public int appPort;
    public TrafficTwin tt;
    public Path stateDir;
    /** Filters installed before the traffic-twin filter (stand for APM instrumentation). */
    public final List<jakarta.servlet.Filter> preFilters = new ArrayList<>();
    /** Extra servlets of the app by path. */
    public final Map<String, HttpServlet> extraServlets = new java.util.LinkedHashMap<>();
    public final HttpClient plain = HttpClient.newHttpClient();
    public final HttpClient wrapped = TrafficTwinHttpClient.wrap(HttpClient.newHttpClient());

    public Harness() throws Exception {
        carrier = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        carrier.createContext("/", this::carrierHandle);
        carrier.start();
        carrierUrl = "http://127.0.0.1:" + carrier.getAddress().getPort();
    }

    private void carrierHandle(HttpExchange ex) throws IOException {
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        carrierSeen.add(new Seen(ex.getRequestMethod(), ex.getRequestURI().toString(), Map.copyOf(ex.getRequestHeaders()), body));
        String resp;
        if (ex.getRequestMethod().equals("POST")) resp = "{\"shipmentId\":\"SHP-5521\",\"status\":\"BOOKED\"}";
        else resp = "{\"items\":[{\"shipmentId\":\"SHP-5521\",\"status\":\"READY\"}]}";
        byte[] b = resp.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("content-type", "application/json");
        ex.sendResponseHeaders(201, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }

    /** Policy for the shop app and the carrier. */
    public Map<String, Object> policy() {
        Map<String, Object> p = FakeCore.basePolicy();
        Object hmacOrder = map("action", "hmac", "domain", "order");
        Object keep = map("action", "keep");
        p.put("services", list(
            map("name", "carrier", "match", map("base", carrierUrl), "ops", list(
                map("op", "POST /v1/shipments",
                    "request", map("body", list(map("path", "$.orderId", "action", hmacOrder))),
                    "response", map("body", list(map("path", "$.status", "action", keep)))),
                map("op", "GET /v1/shipments", "request", map("query", map("orderId", hmacOrder))))),
            map("name", "shop-api", "match", map("inbound", true, "internal", false), "ops", list(
                map("op", "POST /orders", "response", map("body", list(
                    map("path", "$.id", "action", hmacOrder),
                    map("path", "$.status", "action", keep),
                    map("path", "$.total", "action", map("action", "bucket", "kind", "num", "bounds", list(0L, 50L, 100L, 250L)))))),
                map("op", "GET /orders/{id}", "request", map("path", map("id", hmacOrder))),
                map("op", "GET /api/orders/{id}", "request", map("path", map("id", hmacOrder)))))));
        return p;
    }

    /** Starts everything. {@code withAgent} false leaves the filter installed but the agent stopped. */
    public Harness start(Map<String, Object> policy, boolean exportFast) throws Exception {
        startJetty();
        return startAgent(policy, exportFast);
    }

    /** Starts the fake tt-core and the agent (the app must already be running or not needed). */
    public Harness startAgent(Map<String, Object> policy, boolean exportFast) throws Exception {
        core = new FakeCore(pki(), policy);
        stateDir = Files.createTempDirectory("tt-state");
        Config cfg = new Config();
        cfg.enrollUrl = core.url;
        cfg.enrollToken = core.token;
        cfg.hmacKey = HMAC_KEY;
        cfg.serviceName = "shop-api";
        cfg.stateDir = stateDir.resolve("s");
        cfg.exportFlushMs = exportFast ? 100 : 1000;
        cfg.heartbeatIntervalMs = 300;
        cfg.policyPollIntervalMs = 300;
        tt = TrafficTwin.start(cfg);
        tt.ready().get(60, java.util.concurrent.TimeUnit.SECONDS);
        if (!core.waitFor(c -> tt.state().equals("capturing"), 10_000)) throw new IllegalStateException("not capturing: " + tt.state() + " " + core.heartbeats);
        return this;
    }

    /** Starts only the app (filter installed, agent never started): the baseline of coexistence tests. */
    public Harness startAppOnly() throws Exception {
        startJetty();
        return this;
    }

    private void startJetty() throws Exception {
        jetty = new Server();
        ServerConnector c = new ServerConnector(jetty);
        c.setHost("127.0.0.1");
        jetty.addConnector(c);
        ServletContextHandler ctx = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
        ctx.setContextPath("/");
        for (jakarta.servlet.Filter f : preFilters) ctx.addFilter(new FilterHolder(f), "/*", EnumSet.of(DispatcherType.REQUEST, DispatcherType.ASYNC));
        ctx.addFilter(new FilterHolder(new TrafficTwinFilter()), "/*", EnumSet.of(DispatcherType.REQUEST, DispatcherType.ASYNC));
        extraServlets.forEach((path, servlet) -> ctx.addServlet(new ServletHolder(servlet), path));
        ctx.addServlet(new ServletHolder(new ShopServlet()), "/orders");
        ctx.addServlet(new ServletHolder(new SpringLikeServlet("/orders/{orderId}")), "/");
        ctx.addServlet(new ServletHolder(new SpringLikeServlet("/orders/{orderId}")), "/api/*");
        ctx.addServlet(new ServletHolder(new AsyncServlet()), "/async");
        ctx.addServlet(new ServletHolder(new EchoServlet()), "/echo");
        jetty.setHandler(ctx);
        jetty.start();
        appPort = c.getLocalPort();
    }

    public String appUrl(String path) {
        return "http://127.0.0.1:" + appPort + path;
    }

    public HttpResponse<String> call(String method, String path, Map<String, String> headers, String body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(appUrl(path)));
        headers.forEach(b::header);
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return plain.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    public static final String ORDER_BODY =
        "{\"items\":[{\"sku\":\"TSHIRT-RED-M\",\"qty\":2}],\"email\":\"giulia.neri@example.com\",\"note\":\"\"}";

    /** Waits until the core holds at least {@code n} events more than {@code before}. */
    public boolean waitEvents(int n) throws InterruptedException {
        return core.waitFor(c -> c.events.size() >= n, 10_000);
    }

    @Override
    public void close() throws Exception {
        if (tt != null) tt.stop();
        if (jetty != null) jetty.stop();
        carrier.stop(0);
        if (core != null) core.close();
    }

    // --- the app -----------------------------------------------------------------------------

    /** POST /orders creates an order and books a shipment (two outbound calls); GET /orders/{id} reads one. */
    private final class ShopServlet extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
            String in = new String(req.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            try {
                HttpRequest ship = HttpRequest.newBuilder(URI.create(carrierUrl + "/v1/shipments"))
                    .header("content-type", "application/json").header("authorization", "Bearer carrier-api-key")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"orderId\":\"ORD-2026-000184\",\"email\":\"giulia.neri@example.com\"}")).build();
                wrapped.send(ship, HttpResponse.BodyHandlers.ofString());
                wrapped.send(HttpRequest.newBuilder(URI.create(carrierUrl + "/v1/shipments?orderId=ORD-2026-000184")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            res.addCookie(new Cookie("cart", "abc123def456"));
            res.setStatus(201);
            res.setContentType("application/json; charset=utf-8");
            res.getWriter().write("{\"id\":\"ORD-2026-000184\",\"status\":\"CREATED\",\"total\":73.40,\"echo\":" + in.length() + ",\"email\":\"giulia.neri@example.com\"}");
        }

    }

    /** Stands for Spring's DispatcherServlet: after handler mapping it stores the best matching pattern. */
    private static final class SpringLikeServlet extends HttpServlet {
        private final String pattern;

        SpringLikeServlet(String pattern) {
            this.pattern = pattern;
        }

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
            req.setAttribute("org.springframework.web.servlet.HandlerMapping.bestMatchingPattern", pattern);
            res.setContentType("application/json");
            res.getOutputStream().write("{\"status\":\"CREATED\"}".getBytes(StandardCharsets.UTF_8));
        }
    }

    private static final class AsyncServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse res) {
            AsyncContext ac = req.startAsync();
            new Thread(() -> {
                try {
                    Thread.sleep(50);
                    ac.getResponse().setContentType("application/json");
                    ac.getResponse().getWriter().write("{\"async\":true}");
                } catch (Exception e) {
                    // test app
                } finally {
                    ac.complete();
                }
            }).start();
        }
    }

    private static final class EchoServlet extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
            byte[] b = req.getInputStream().readAllBytes();
            res.setContentType("application/octet-stream");
            res.getOutputStream().write(b);
        }

        @Override
        protected void doPut(HttpServletRequest req, HttpServletResponse res) throws IOException {
            // Reads only part of the body: "not consumed".
            req.getInputStream().read();
            res.setStatus(204);
        }
    }

    @SuppressWarnings("unused")
    private static List<String> unused() {
        return new ArrayList<>();
    }
}
