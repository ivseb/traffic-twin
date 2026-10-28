// RT-JAVA-1 (medium): the Java SDK buffers the WHOLE Fleet response in memory before applying its cap.
//
// sdk/java/.../fleet/FleetClient.java send() uses HttpResponse.BodyHandlers.ofByteArray() and only
// then truncates to maxBody (8 MiB for GET /fleet/v1/policy, 1 MiB for heartbeat, renew, enroll).
// A tt-core (compromised, or buggy proxy in front of it) that streams a large body makes the
// application JVM -- the SDK runs inside production -- allocate the whole body: OutOfMemoryError in
// the tt-fleet thread, and in the application's threads that allocate at the same time (M12).
// TrafficTwin.guarded() catches RuntimeException only, so an Error thrown by a periodic task also
// cancels that task for good (ScheduledThreadPoolExecutor suppresses later runs): after one OOM the
// source never polls the policy again (closing policies are no longer applied until not_after).
//
// Run (exit 0 = fixed; exit 3 = VULNERABLE, the JVM hit OutOfMemoryError -- -XX:+ExitOnOutOfMemoryError makes the first
// OOM in any thread, including the HttpClient selector, terminate with code 3; exit 1 = VULNERABLE, read never ended):
//   docker run --rm -v "$PWD":/repo:ro eclipse-temurin:17 sh -c 'javac -d /tmp/o -sourcepath /repo/sdk/java/sdk/src/main/java /repo/test/redteam/java/RtFleetResponseCap.java && java -Xmx128m -XX:+ExitOnOutOfMemoryError -cp /tmp/o RtFleetResponseCap'
//
// Plain HTTP on loopback: the property under test (bounded read) does not depend on TLS.

import com.sun.net.httpserver.HttpServer;
import io.github.ivseb.traffictwin.fleet.FleetClient;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;

public final class RtFleetResponseCap {
    public static void main(String[] args) throws Exception {
        HttpServer srv = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        srv.createContext("/", ex -> {
            ex.sendResponseHeaders(200, 0); // chunked
            byte[] buf = new byte[1 << 20];
            java.util.Arrays.fill(buf, (byte) ' ');
            try (OutputStream os = ex.getResponseBody()) {
                for (int i = 0; i < 512; i++) os.write(buf); // 512 MiB of JSON whitespace
            } catch (Exception e) {
                // client went away: expected once it stops reading
            }
        });
        srv.start();
        URI u = URI.create("http://127.0.0.1:" + srv.getAddress().getPort() + "/fleet/v1/policy");
        int[] code = {1};
        String[] what = {"VULNERABLE: the read of a 512 MiB policy answer (cap 8 MiB) neither finished nor failed within 60 s: "
            + "OutOfMemoryError in the HttpClient threads (heap " + (Runtime.getRuntime().maxMemory() >> 20) + " MiB)"};
        byte[] vulnerable = (what[0] + "\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII); // allocated before the heap fills up
        Thread t = new Thread(() -> {
            try {
                FleetClient.Response r = FleetClient.send(HttpClient.newHttpClient(), "GET", u, null, null, Duration.ofSeconds(60), 8 << 20);
                what[0] = "ok: answer bounded to " + r.body().length + " bytes";
                code[0] = 0;
            } catch (java.io.IOException e) {
                what[0] = "ok: refused (" + e.getClass().getSimpleName() + ")";
                code[0] = 0;
            } catch (OutOfMemoryError e) {
                what[0] = "VULNERABLE: OutOfMemoryError while reading a 512 MiB policy answer with an 8 MiB cap";
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "tt-fleet");
        t.setDaemon(true);
        t.start();
        try {
            t.join(60_000);
            System.out.write(code[0] == 0 ? (what[0] + "\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII) : vulnerable);
            System.out.flush();
        } catch (Throwable e) {
            System.out.write(vulnerable, 0, vulnerable.length);
            System.out.flush();
        }
        Runtime.getRuntime().halt(code[0]);
    }
}
