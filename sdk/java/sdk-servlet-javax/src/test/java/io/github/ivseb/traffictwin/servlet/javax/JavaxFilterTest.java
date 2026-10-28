package io.github.ivseb.traffictwin.servlet.javax;

import static io.github.ivseb.traffictwin.support.FakeCore.list;
import static io.github.ivseb.traffictwin.support.FakeCore.map;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.ivseb.traffictwin.Config;
import io.github.ivseb.traffictwin.TrafficTwin;
import io.github.ivseb.traffictwin.support.FakeCore;
import io.github.ivseb.traffictwin.support.TestPki;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.util.EnumSet;
import java.util.Map;
import javax.servlet.DispatcherType;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.junit.jupiter.api.Test;

/** The generated javax.servlet variant, on Jetty 10 (Servlet 4): same capture, same event. */
class JavaxFilterTest {
    @Test
    void javaxFilterCapturesAndLeavesTheTrafficAlone() throws Exception {
        try (TestPki pki = new TestPki()) {
            Map<String, Object> policy = FakeCore.basePolicy();
            policy.put("services", list(map("name", "shop-api", "match", map("inbound", true, "internal", false), "ops", list(
                map("op", "POST /echo", "response", map("body", list(map("path", "$.status", "action", map("action", "keep")))))))));
            try (FakeCore core = new FakeCore(pki, policy)) {
                Server jetty = new Server();
                ServerConnector c = new ServerConnector(jetty);
                c.setHost("127.0.0.1");
                jetty.addConnector(c);
                ServletContextHandler ctx = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
                ctx.addFilter(new FilterHolder(new TrafficTwinFilter()), "/*", EnumSet.of(DispatcherType.REQUEST, DispatcherType.ASYNC));
                ctx.addServlet(new ServletHolder(new HttpServlet() {
                    @Override
                    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
                        byte[] in = req.getInputStream().readAllBytes();
                        res.setContentType("application/json");
                        res.getWriter().write("{\"status\":\"OK\",\"len\":" + in.length + ",\"who\":\"giulia.neri@example.com\"}");
                    }
                }), "/echo");
                jetty.setHandler(ctx);
                jetty.start();
                Config cfg = new Config();
                cfg.enrollUrl = core.url;
                cfg.enrollToken = core.token;
                cfg.hmacKey = "k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
                cfg.serviceName = "shop-api";
                cfg.stateDir = Files.createTempDirectory("tt-javax").resolve("s");
                cfg.exportFlushMs = 100;
                cfg.heartbeatIntervalMs = 300;
                TrafficTwin tt = TrafficTwin.start(cfg);
                try {
                    tt.ready().get(60, java.util.concurrent.TimeUnit.SECONDS);
                    assertTrue(core.waitFor(x -> tt.state().equals("capturing"), 10_000), tt.state());
                    HttpResponse<String> r = HttpClient.newHttpClient().send(
                        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + c.getLocalPort() + "/echo")).header("content-type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString("{\"email\":\"giulia.neri@example.com\"}")).build(),
                        HttpResponse.BodyHandlers.ofString());
                    assertEquals(200, r.statusCode());
                    assertEquals("{\"status\":\"OK\",\"len\":35,\"who\":\"giulia.neri@example.com\"}", r.body());
                    assertTrue(core.waitFor(x -> !x.events.isEmpty(), 10_000));
                    String ev = core.eventStrings.get(0);
                    assertTrue(ev.contains("\"op\":\"POST /echo\""), ev);
                    assertTrue(ev.contains("\"email\":\"drop:str:email\""), ev);
                    assertTrue(ev.contains("\"status\":\"keep:OK\""), ev);
                    assertTrue(ev.contains("\"who\":\"drop:str:email\""), ev);
                    assertFalse(ev.contains("giulia"));
                    assertEquals("sdk-java", ((Map<?, ?>) core.events.get(0).get("source")).get("kind"));
                } finally {
                    tt.stop();
                    jetty.stop();
                }
            }
        }
    }
}
