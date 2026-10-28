package io.github.ivseb.traffictwin.fleet;

import io.github.ivseb.traffictwin.sanitizer.Base64Url;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/** Certificates, pins and TLS contexts (JDK only). */
public final class Pki {
    private Pki() {}

    private static final Pattern PEM_BLOCK = Pattern.compile("-----BEGIN ([A-Z0-9 ]+)-----([A-Za-z0-9+/=\\s]+)-----END \\1-----");

    /** DER bytes of every PEM block with the given label. */
    public static List<byte[]> pemBlocks(String pem, String label) {
        List<byte[]> out = new ArrayList<>();
        Matcher m = PEM_BLOCK.matcher(pem);
        while (m.find()) {
            if (m.group(1).equals(label)) out.add(Base64.getMimeDecoder().decode(m.group(2).replaceAll("\\s", "")));
        }
        return out;
    }

    public static String toPem(String label, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
    }

    /** CA pin (fleet-api): base64url(SHA-256(DER of the root certificate)). */
    public static String pinOf(byte[] der) {
        try {
            return Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(der));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static List<X509Certificate> parseCerts(String pem) throws GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> out = new ArrayList<>();
        for (byte[] der : pemBlocks(pem, "CERTIFICATE")) out.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
        return out;
    }

    /** PKCS#8 private key (PEM) of any algorithm the JDK knows. */
    public static PrivateKey parsePrivateKey(String pem) throws GeneralSecurityException {
        List<byte[]> blocks = pemBlocks(pem, "PRIVATE KEY");
        if (blocks.isEmpty()) throw new GeneralSecurityException("no PKCS#8 key");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(blocks.get(0));
        GeneralSecurityException last = null;
        for (String alg : new String[] {"EC", "Ed25519", "RSA", "RSASSA-PSS"}) {
            try {
                return KeyFactory.getInstance(alg).generatePrivate(spec);
            } catch (GeneralSecurityException e) {
                last = e;
            }
        }
        throw last;
    }

    /** PKCS#12 keystore with the client key and chain. */
    public static KeyStore keyStore(PrivateKey key, List<X509Certificate> chain, char[] password) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("client", key, password, chain.toArray(new Certificate[0]));
        return ks;
    }

    private static KeyStore trustStore(List<X509Certificate> anchors) throws GeneralSecurityException, IOException {
        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        int i = 0;
        for (X509Certificate c : anchors) ts.setCertificateEntry("ca" + i++, c);
        return ts;
    }

    /** TLS context that trusts only {@code anchors} (server authentication, no client certificate). */
    public static SSLContext trustOnly(List<X509Certificate> anchors) throws GeneralSecurityException, IOException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore(anchors));
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        return ctx;
    }

    /** mTLS context: the client key and chain, trusting only {@code anchors}. */
    public static SSLContext mtls(KeyStore clientKeys, char[] password, List<X509Certificate> anchors) throws GeneralSecurityException, IOException {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(clientKeys, password);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore(anchors));
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }

    /**
     * Opens a TLS connection without trusting anything and returns the chain the server presents.
     * The caller must check the root against the pin before trusting any of it.
     */
    public static List<X509Certificate> presentedChain(URI url, int timeoutMs) throws GeneralSecurityException, IOException {
        X509TrustManager acceptAll = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[] {acceptAll}, null);
        int port = url.getPort() > 0 ? url.getPort() : 443;
        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket()) {
            s.connect(new java.net.InetSocketAddress(url.getHost(), port), timeoutMs);
            s.setSoTimeout(timeoutMs);
            s.startHandshake();
            List<X509Certificate> out = new ArrayList<>();
            for (Certificate c : s.getSession().getPeerCertificates()) out.add((X509Certificate) c);
            return out;
        }
    }
}
