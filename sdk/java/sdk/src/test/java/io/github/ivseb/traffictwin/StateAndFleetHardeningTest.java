package io.github.ivseb.traffictwin;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.ivseb.traffictwin.fleet.FleetClient;
import io.github.ivseb.traffictwin.fleet.StateStore;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/** Red team round 2 regressions: bounded Fleet answers, private state directory, untrusted state files. */
class StateAndFleetHardeningTest {
    private static HttpServer server(Consumer<HttpExchange> h) throws IOException {
        HttpServer s = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        s.createContext("/", ex -> {
            try {
                h.accept(ex);
            } finally {
                ex.close();
            }
        });
        s.start();
        return s;
    }

    private static URI uri(HttpServer s) {
        return URI.create("http://127.0.0.1:" + s.getAddress().getPort() + "/fleet/v1/policy");
    }

    @Test
    void answerBeyondTheCapIsAbandonedAndNeverBuffered() throws Exception {
        HttpServer s = server(ex -> {
            try {
                ex.sendResponseHeaders(200, 0);
                byte[] buf = new byte[1 << 16];
                try (OutputStream os = ex.getResponseBody()) {
                    for (int i = 0; i < 4096; i++) os.write(buf); // 256 MiB
                }
            } catch (IOException e) {
                // the client hung up
            }
        });
        try {
            IOException e = assertThrows(IOException.class,
                () -> FleetClient.send(HttpClient.newHttpClient(), "GET", uri(s), null, null, Duration.ofSeconds(10), 1 << 20));
            assertTrue(e.getMessage() != null && e.getMessage().contains("too_large"), String.valueOf(e.getMessage()));
        } finally {
            s.stop(0);
        }
    }

    @Test
    void gzipAnswerIsBoundedAfterDecompression() throws Exception {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try (GZIPOutputStream g = new GZIPOutputStream(bo)) {
            g.write(new byte[64 << 20]); // a 64 MiB bomb of a few dozen KiB
        }
        byte[] bomb = bo.toByteArray();
        HttpServer s = server(ex -> {
            try {
                ex.getResponseHeaders().add("Content-Encoding", "gzip");
                ex.sendResponseHeaders(200, bomb.length);
                ex.getResponseBody().write(bomb);
            } catch (IOException e) {
                // ignore
            }
        });
        try {
            assertThrows(IOException.class,
                () -> FleetClient.send(HttpClient.newHttpClient(), "GET", uri(s), null, null, Duration.ofSeconds(10), 1 << 20));
        } finally {
            s.stop(0);
        }
    }

    @Test
    void stalledBodyTimesOut() throws Exception {
        HttpServer s = server(ex -> {
            try {
                ex.sendResponseHeaders(200, 0);
                OutputStream os = ex.getResponseBody();
                os.write('{');
                os.flush();
                Thread.sleep(4_000); // headers sent, body never finishes
            } catch (IOException | InterruptedException e) {
                // the client gave up
            }
        });
        try {
            long t0 = System.nanoTime();
            assertThrows(IOException.class,
                () -> FleetClient.send(HttpClient.newHttpClient(), "GET", uri(s), null, null, Duration.ofSeconds(1), 1 << 20));
            assertTrue(Duration.ofNanos(System.nanoTime() - t0).toSeconds() < 10);
        } finally {
            s.stop(0);
        }
    }

    @Test
    void wellFormedAnswerStillWorks() throws Exception {
        HttpServer s = server(ex -> {
            try {
                byte[] b = "{\"ok\":true}".getBytes();
                ex.sendResponseHeaders(200, b.length);
                ex.getResponseBody().write(b);
            } catch (IOException e) {
                // ignore
            }
        });
        try {
            FleetClient.Response r = FleetClient.send(HttpClient.newHttpClient(), "GET", uri(s), null, null, Duration.ofSeconds(5), 1 << 20);
            assertEquals(200, r.status());
            assertArrayEquals("{\"ok\":true}".getBytes(), r.body());
        } finally {
            s.stop(0);
        }
    }

    @Test
    void widerStateDirectoriesAreRepairedAndLooseFilesAreNotTrusted() throws Exception {
        Path base = Files.createTempDirectory("tt-state-");
        Assumptions.assumeTrue(Files.getFileStore(base).supportsFileAttributeView("posix"));
        Path root = base.resolve(".traffic-twin");
        Path leaf = root.resolve("abc");
        Files.createDirectories(leaf);
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxr-xr-x"));
        Files.setPosixFilePermissions(leaf, PosixFilePermissions.fromString("rwxrwxrwx"));
        List<String> seen = new ArrayList<>();
        StateStore st = new StateStore(leaf, seen::add);
        assertTrue(st.prepare());
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(root)));
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(leaf)));
        st.writeText("state.json", "{}");
        assertEquals("{}", st.readText("state.json"));
        Files.setPosixFilePermissions(leaf.resolve("state.json"), PosixFilePermissions.fromString("rw-rw-rw-"));
        assertNull(st.readText("state.json"));
        assertEquals(List.of("state_file_untrusted"), seen);
        st.writeText("keystore.pass", "pw");
        Files.setPosixFilePermissions(leaf.resolve("keystore.pass"), PosixFilePermissions.fromString("rw-r--r--"));
        assertEquals("pw", st.readText("keystore.pass"));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(leaf.resolve("keystore.pass"))));
        Files.createSymbolicLink(leaf.resolve("enrollment.json"), Path.of("/etc/hosts"));
        assertNull(st.readText("enrollment.json"));
    }
}
