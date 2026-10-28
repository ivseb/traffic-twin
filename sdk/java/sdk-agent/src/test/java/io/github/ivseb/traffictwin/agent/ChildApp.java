package io.github.ivseb.traffictwin.agent;

import com.sun.net.httpserver.HttpServer;
import io.github.ivseb.traffictwin.support.FakeCore;
import io.github.ivseb.traffictwin.support.Harness;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
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
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static io.github.ivseb.traffictwin.support.FakeCore.list;
import static io.github.ivseb.traffictwin.support.FakeCore.map;

/**
 * A rig for the integration tests: a fake carrier and a fake tt-core in this JVM, and the application
 * (embedded Tomcat or Jetty) in a child JVM started with {@code -javaagent} flags and nothing else.
 */
final class ChildApp implements AutoCloseable {
    static final String AGENT = System.getProperty("tt.agent.jar");
    static final Path LIBS = Path.of(System.getProperty("tt.it.libs", "target/it-libs"));
    static final Path OTEL_AGENT = LIBS.resolve("opentelemetry-javaagent.jar");
    static final Path OTEL_EXTENSION = Path.of("..", "sdk-otel-extension", "target", "sdk-otel-extension-0.1.0.jar").toAbsolutePath().normalize();

    /** A request seen by the carrier. */
    record Seen(String method, String uri, Map<String, List<String>> headers, String body) {}

    final HttpServer carrier;
    final String carrierUrl;
    final List<Seen> carrierSeen = new CopyOnWriteArrayList<>();
    final FakeCore core;
    final List<String> output = new CopyOnWriteArrayList<>();
    Process process;
    int port;
    final HttpClient http = HttpClient.newHttpClient();

    ChildApp() throws Exception {
        carrier = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        carrier.createContext("/", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            carrierSeen.add(new Seen(ex.getRequestMethod(), ex.getRequestURI().toString(), Map.copyOf(ex.getRequestHeaders()), body));
            byte[] b = "{\"shipmentId\":\"SHP-5521\",\"status\":\"BOOKED\"}".getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("content-type", "application/json");
            ex.sendResponseHeaders(201, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        carrier.start();
        carrierUrl = "http://127.0.0.1:" + carrier.getAddress().getPort();
        core = new FakeCore(Harness.pki(), policy());
    }

    private Map<String, Object> policy() {
        Map<String, Object> p = FakeCore.basePolicy();
        Object hmacOrder = map("action", "hmac", "domain", "order");
        Object keep = map("action", "keep");
        p.put("services", list(
            map("name", "carrier", "match", map("base", carrierUrl), "ops", list(
                map("op", "POST /v1/shipments",
                    "request", map("body", list(map("path", "$.orderId", "action", hmacOrder))),
                    "response", map("body", list(map("path", "$.status", "action", keep)))))),
            map("name", "shop-api", "match", map("inbound", true, "internal", false), "ops", list(
                map("op", "POST /orders", "response", map("body", list(map("path", "$.status", "action", keep))))))));
        return p;
    }

    /**
     * Starts the application. {@code flavour} is tomcat, tomcat9 or jetty; {@code jvmArgs} go before
     * the class path (the -javaagent flags, in the order given).
     */
    ChildApp start(String flavour, List<String> jvmArgs, Map<String, String> extraEnv, String outbound) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        cmd.addAll(jvmArgs);
        cmd.add("-Dtt.app.carrier=" + carrierUrl);
        cmd.add("-Dtt.app.outbound=" + outbound);
        cmd.add("-cp");
        cmd.add(classpath(flavour));
        cmd.add("io.github.ivseb.traffictwin.agent.apps.Main");
        cmd.add(flavour);
        ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
        Map<String, String> env = pb.environment();
        env.keySet().removeIf(k -> k.startsWith("TT_") || k.startsWith("OTEL_") || k.equals("JAVA_TOOL_OPTIONS"));
        env.putAll(extraEnv);
        process = pb.start();
        Thread reader = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                for (String line; (line = r.readLine()) != null; ) output.add(line);
            } catch (IOException e) {
                // process ended
            }
        }, "child-output");
        reader.setDaemon(true);
        reader.start();
        long t0 = System.currentTimeMillis();
        while (port == 0 && System.currentTimeMillis() - t0 < 90_000) {
            for (String l : output) if (l.startsWith("PORT=")) port = Integer.parseInt(l.substring(5).trim());
            if (!process.isAlive() && port == 0) throw new IllegalStateException("app died:\n" + String.join("\n", output));
            Thread.sleep(50);
        }
        if (port == 0) throw new IllegalStateException("app did not start:\n" + String.join("\n", output));
        return this;
    }

    /** TT_* environment pointing at the fake tt-core. */
    Map<String, String> ttEnv() throws Exception {
        Map<String, String> e = new java.util.LinkedHashMap<>();
        e.put("TT_ENROLL_URL", core.url);
        e.put("TT_ENROLL_TOKEN", core.token);
        e.put("TT_HMAC_KEY", Harness.HMAC_KEY);
        e.put("TT_SERVICE_NAME", "shop-api");
        e.put("TT_STATE_DIR", Files.createTempDirectory("tt-state").resolve("s").toString());
        e.put("TT_HEARTBEAT_INTERVAL_MS", "300");
        e.put("TT_POLICY_POLL_INTERVAL_MS", "300");
        e.put("TT_EXPORT_FLUSH_MS", "100");
        e.put("TT_DEBUG", "1");
        return e;
    }

    /** Sends a request and, if the agent is there, waits until the SDK is capturing (first request starts it lazily). */
    HttpResponse<String> post(String path, String body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
            .header("content-type", "application/json").header("cookie", "sid=9f8e7d6c5b4a")
            .POST(HttpRequest.BodyPublishers.ofString(body)).build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    /** Warms the app until the SDK reports "capturing", so that the request under test is sampled. */
    void awaitCapturing() throws Exception {
        long t0 = System.currentTimeMillis();
        while (System.currentTimeMillis() - t0 < 60_000) {
            http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/health")).GET().build(), HttpResponse.BodyHandlers.ofString());
            if ("capturing".equals(core.lastHeartbeatState())) return;
            Thread.sleep(100);
        }
        throw new IllegalStateException("never capturing; heartbeats=" + core.heartbeats + " enrollments=" + core.enrollments.size()
            + "\n" + String.join("\n", output) + "\n" + threadDump());
    }

    /** Thread names and top frames of the child's tt-* threads, for failure messages. */
    String threadDump() {
        try {
            Process p = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "jstack").toString(), String.valueOf(process.pid()))
                .redirectErrorStream(true).start();
            String all = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            StringBuilder sb = new StringBuilder();
            for (String block : all.split("\n\n")) if (block.contains("\"tt-") || block.contains("traffictwin")) sb.append(block, 0, Math.min(block.length(), 1500)).append("\n\n");
            return sb.toString();
        } catch (Exception e) {
            return "no thread dump: " + e;
        }
    }

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> events() {
        return core.events.stream().map(e -> (Map<String, Object>) (Object) e).collect(Collectors.toList());
    }

    static String classpath(String flavour) {
        List<String> keep = new ArrayList<>();
        Pattern sdk = Pattern.compile(".*(/sdk/target/|/sdk-servlet-javax/target/|/sdk-otel-extension/target/|/sdk-agent/target/classes|/io/github/ivseb/traffictwin/).*");
        if (flavour.equals("tomcat9")) {
            for (File f : LIBS.resolve("tomcat9").toFile().listFiles()) keep.add(f.getPath());
            keep.add(Path.of("target", "test-classes").toAbsolutePath().toString());
            return String.join(File.pathSeparator, keep);
        }
        for (String e : System.getProperty("java.class.path").split(File.pathSeparator)) {
            String n = e.replace('\\', '/');
            if (sdk.matcher(n).matches() && !n.endsWith("/test-classes")) continue;
            if (n.endsWith("/sdk-agent/target/test-classes")) {
                keep.add(e);
                continue;
            }
            String base = n.substring(n.lastIndexOf('/') + 1);
            boolean tomcatJar = base.startsWith("tomcat-");
            boolean jettyJar = base.startsWith("jetty-") || base.startsWith("jakarta.servlet-api");
            if (flavour.equals("tomcat") && (jettyJar || base.startsWith("javax.servlet-api"))) continue;
            if (flavour.equals("jetty") && tomcatJar) continue;
            if (base.startsWith("junit") || base.startsWith("opentest4j") || base.startsWith("apiguardian")) continue;
            keep.add(e);
        }
        return String.join(File.pathSeparator, keep);
    }

    @Override
    public void close() throws Exception {
        if (process != null) {
            process.destroy();
            if (!process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)) process.destroyForcibly();
        }
        carrier.stop(0);
        core.close();
    }
}
