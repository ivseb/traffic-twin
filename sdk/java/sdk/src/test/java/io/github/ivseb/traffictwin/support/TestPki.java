package io.github.ivseb.traffictwin.support;

import io.github.ivseb.traffictwin.fleet.Pki;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Comparator;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Test PKI built with the JDK's own {@code keytool}: a CA, a server certificate and client certificates. */
public final class TestPki implements AutoCloseable {
    private static final char[] PW = "changeit".toCharArray();
    private final Path dir;
    private final AtomicInteger n = new AtomicInteger();
    public final KeyStore server;
    public final X509Certificate ca;

    public TestPki() throws Exception {
        dir = Files.createTempDirectory("tt-pki");
        keytool("-genkeypair", "-alias", "ca", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=tt test CA", "-ext", "bc:c",
            "-validity", "30", "-keystore", "ca.p12", "-storetype", "PKCS12", "-storepass", "changeit", "-keypass", "changeit");
        keytool("-exportcert", "-alias", "ca", "-keystore", "ca.p12", "-storepass", "changeit", "-rfc", "-file", "ca.pem");
        ca = Pki.parseCerts(Files.readString(dir.resolve("ca.pem"))).get(0);
        issue("server", "CN=localhost", "san=ip:127.0.0.1,dns:localhost");
        server = load("server.p12");
    }

    private void keytool(String... args) throws IOException, InterruptedException {
        String[] cmd = new String[args.length + 1];
        cmd[0] = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        System.arraycopy(args, 0, cmd, 1, args.length);
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true).start();
        byte[] out;
        try (InputStream in = p.getInputStream()) {
            out = in.readAllBytes();
        }
        if (!p.waitFor(60, TimeUnit.SECONDS) || p.exitValue() != 0) {
            throw new IllegalStateException("keytool failed: " + String.join(" ", args) + "\n" + new String(out, StandardCharsets.UTF_8));
        }
    }

    private void issue(String alias, String dn, String san) throws IOException, InterruptedException {
        String ks = alias + ".p12";
        keytool("-genkeypair", "-alias", alias, "-keyalg", "EC", "-groupname", "secp256r1", "-dname", dn, "-validity", "30", "-keystore", ks,
            "-storetype", "PKCS12", "-storepass", "changeit", "-keypass", "changeit");
        keytool("-certreq", "-alias", alias, "-keystore", ks, "-storepass", "changeit", "-file", alias + ".csr");
        keytool("-gencert", "-alias", "ca", "-keystore", "ca.p12", "-storepass", "changeit", "-infile", alias + ".csr", "-outfile", alias + ".crt",
            "-ext", san, "-ext", "eku=clientAuth,serverAuth", "-validity", "30", "-rfc");
        keytool("-importcert", "-noprompt", "-alias", "ca", "-file", "ca.pem", "-keystore", ks, "-storepass", "changeit");
        keytool("-importcert", "-noprompt", "-alias", alias, "-file", alias + ".crt", "-keystore", ks, "-storepass", "changeit");
    }

    private KeyStore load(String file) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(dir.resolve(file))) {
            ks.load(in, PW);
        }
        return ks;
    }

    public char[] password() {
        return PW.clone();
    }

    /** A client identity: certificate (PEM) with the given SAN and its PKCS#8 key (PEM). */
    public record Identity(String certPem, String keyPem) {}

    public Identity issueClient(String sourceId) throws Exception {
        String alias = "client" + n.incrementAndGet();
        issue(alias, "CN=" + sourceId, "san=dns:" + sourceId);
        KeyStore ks = load(alias + ".p12");
        PrivateKey key = (PrivateKey) ks.getKey(alias, PW);
        Certificate[] chain = ks.getCertificateChain(alias);
        return new Identity(Pki.toPem("CERTIFICATE", chain[0].getEncoded()), Pki.toPem("PRIVATE KEY", key.getEncoded()));
    }

    public String caPem() throws Exception {
        return Pki.toPem("CERTIFICATE", ca.getEncoded());
    }

    @Override
    public void close() throws IOException {
        try (var s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }
}
