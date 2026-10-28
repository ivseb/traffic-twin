package io.github.ivseb.traffictwin.support;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import io.github.ivseb.traffictwin.fleet.Pki;
import io.github.ivseb.traffictwin.sanitizer.Base64Url;
import io.github.ivseb.traffictwin.sanitizer.Envelope;
import io.github.ivseb.traffictwin.sanitizer.Json;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * A fake tt-core intake listener for tests (com.sun.net.httpserver): Fleet source endpoints
 * (enroll, heartbeat, policy, renew) and OTLP/HTTP JSON intake, TLS with the root in the chain,
 * mTLS checked on every route except enroll. Invented data only.
 */
public final class FakeCore implements AutoCloseable {
    public static final String SIGNING_KID = "policy-test-1";

    public final TestPki pki;
    public final HttpsServer server;
    public final String url;
    public final String token;
    public final String signingPublicKey;
    private final KeyPair signer;

    // observable state
    public final List<Map<String, Object>> enrollments = new CopyOnWriteArrayList<>();
    public final List<Map<String, Object>> heartbeats = new CopyOnWriteArrayList<>();
    public final List<String> eventStrings = new CopyOnWriteArrayList<>();
    public final List<Map<String, Object>> events = new CopyOnWriteArrayList<>();
    public final List<Map<String, Object>> otlpRequests = new CopyOnWriteArrayList<>();
    public final List<String> clientSans = new CopyOnWriteArrayList<>();
    public volatile int policyFetches;
    public volatile boolean kill;
    public volatile long minIssuedSeq;
    public volatile int failLogs;
    public volatile boolean rejectUnauthenticated = false;
    public volatile String gzipSeen = "";
    /** Heartbeat {@code add_signing_keys} / {@code revoke_signing_keys}; null leaves the field out. */
    public volatile List<Object> addSigningKeys;
    public volatile List<Object> revokeSigningKeys;
    private volatile Map<String, Object> envelope;
    private volatile int logsStatus = 200;

    public FakeCore(TestPki pki, Map<String, Object> policyBody) throws Exception {
        this.pki = pki;
        signer = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] spki = signer.getPublic().getEncoded();
        byte[] raw = java.util.Arrays.copyOfRange(spki, spki.length - 32, spki.length);
        signingPublicKey = Base64Url.encode(raw);
        byte[] secret = new byte[24];
        new SecureRandom().nextBytes(secret);
        token = "tte_" + Base64Url.encode(secret) + "." + Pki.pinOf(pki.ca.getEncoded());
        if (policyBody != null) setPolicy(policyBody);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(pki.server, pki.password());
        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("ca", pki.ca);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(ctx) {
            @Override
            public void configure(HttpsParameters params) {
                var p = ctx.getDefaultSSLParameters();
                p.setWantClientAuth(true);
                params.setSSLParameters(p);
            }
        });
        server.createContext("/", this::handle);
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "fake-core");
            t.setDaemon(true);
            return t;
        }));
        server.start();
        url = "https://127.0.0.1:" + server.getAddress().getPort();
    }

    // --- policy ---------------------------------------------------------------------------

    /** Policy body defaults for tests: capture everything, content-type kept. */
    public static Map<String, Object> basePolicy() {
        Instant now = Instant.now();
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("format", "tt.policy.body/v1");
        p.put("policy_id", "p-shop");
        p.put("version", 1L);
        p.put("issued_seq", 1L);
        p.put("created_at", now.minus(1, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.SECONDS).toString());
        p.put("not_after", now.plus(30, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS).toString());
        p.put("targets", map("groups", list("shop")));
        p.put("hmac", map("kid", "k1", "accept_kids", list(), "epoch", "2026-10"));
        p.put("sampling", map("rate_bp", 10000L, "trust_baggage", false, "propagate_to", list()));
        p.put("segments", map("auto_words", false, "allow", list("v1"), "hosts_allow", list()));
        p.put("limits", map("max_body_bytes", 1048576L, "max_depth", 32L, "max_array", 32L, "max_keys", 256L, "keep_max_bytes", 64L));
        Map<String, Object> keepCt = map("headers", map("content-type", map("action", "keep")));
        p.put("global", map("request", keepCt, "response", keepCt));
        p.put("services", list());
        return p;
    }

    public static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    public static List<Object> list(Object... items) {
        return new ArrayList<>(List.of(items));
    }

    public Map<String, Object> makeEnvelope(Map<String, Object> body) throws Exception {
        return makeEnvelope(body, SIGNING_KID, signer);
    }

    /** The enrollment signing key pair (kid {@link #SIGNING_KID}). */
    public KeyPair signer() {
        return signer;
    }

    public static KeyPair newSigningKey() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    public static byte[] rawPublic(KeyPair kp) {
        byte[] spki = kp.getPublic().getEncoded();
        return java.util.Arrays.copyOfRange(spki, spki.length - 32, spki.length);
    }

    /**
     * An {@code add_signing_keys} entry: {@code kid}'s key endorsed by {@code byKid}'s private key over
     * "tt-fleet-key/v1" || 0x00 || kid || 0x00 || raw public key.
     */
    public static Map<String, Object> endorse(String kid, KeyPair key, String byKid, KeyPair by) throws Exception {
        byte[] raw = rawPublic(key);
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(by.getPrivate());
        s.update(("tt-fleet-key/v1\0" + kid + "\0").getBytes(StandardCharsets.ISO_8859_1));
        s.update(raw);
        return map("kid", kid, "alg", "Ed25519", "public_key", Base64Url.encode(raw), "endorsed_by", byKid, "endorsement", Base64Url.encode(s.sign()));
    }

    public Map<String, Object> makeEnvelope(Map<String, Object> body, String kid, KeyPair key) throws Exception {
        byte[] bytes = Json.writeCanonical(body).getBytes(StandardCharsets.UTF_8);
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(key.getPrivate());
        s.update("tt.policy.body/v1\0".getBytes(StandardCharsets.ISO_8859_1));
        s.update(bytes);
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("format", "tt.policy.compiled/v1");
        env.put("policy_id", body.get("policy_id"));
        env.put("version", body.get("version"));
        env.put("issued_seq", body.get("issued_seq"));
        env.put("hash", "sha256:" + Envelope.sha256Hex(bytes));
        env.put("body_b64", Base64Url.encode(bytes));
        env.put("signature", map("alg", "Ed25519", "kid", kid, "sig", Base64Url.encode(s.sign())));
        return env;
    }

    public void setPolicy(Map<String, Object> body) throws Exception {
        envelope = body == null ? null : makeEnvelope(body);
    }

    /** Serves a policy signed by {@code kid}/{@code key}; returns its envelope hash. */
    public String setPolicy(Map<String, Object> body, String kid, KeyPair key) throws Exception {
        Map<String, Object> env = makeEnvelope(body, kid, key);
        envelope = env;
        return (String) env.get("hash");
    }

    // --- handler --------------------------------------------------------------------------

    private void send(HttpExchange ex, int status, Object body, String... headers) throws IOException {
        byte[] b = body == null ? new byte[0] : Json.writeCanonical(body).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("content-type", "application/json");
        for (int i = 0; i < headers.length; i += 2) ex.getResponseHeaders().set(headers[i], headers[i + 1]);
        if (status == 304) ex.sendResponseHeaders(304, -1);
        else {
            ex.sendResponseHeaders(status, b.length == 0 ? -1 : b.length);
            if (b.length > 0) ex.getResponseBody().write(b);
        }
        ex.close();
    }

    @SuppressWarnings("unchecked")
    private void handle(HttpExchange ex) throws IOException {
        try {
            byte[] body = ex.getRequestBody().readAllBytes();
            String path = ex.getRequestURI().getPath();
            String method = ex.getRequestMethod();
            if (path.equals("/fleet/v1/enroll") && method.equals("POST")) {
                Map<String, Object> j = (Map<String, Object>) Json.parsePlain(body, false);
                if (!token.equals(j.get("token"))) {
                    send(ex, 401, map("code", "token", "message", "unknown token"));
                    return;
                }
                enrollments.add(j);
                String sourceId = "src-" + Long.toHexString(new SecureRandom().nextLong() & 0xffffffffffL);
                TestPki.Identity id = pki.issueClient(sourceId);
                Map<String, Object> src = (Map<String, Object>) j.get("source");
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("source_id", sourceId);
                r.put("group", "shop");
                r.put("service_name", src.get("service_name"));
                r.put("client_cert", id.certPem());
                r.put("client_key", id.keyPem());
                r.put("ca_chain", pki.caPem());
                r.put("policy_signing_keys", list(map("kid", SIGNING_KID, "alg", "Ed25519", "public_key", signingPublicKey)));
                r.put("intake_url", url + "/v1/logs");
                r.put("fleet_url", url);
                r.put("policy_max_age_s", 86400L);
                r.put("heartbeat_interval_s", 30L);
                r.put("policy_poll_interval_s", 60L);
                send(ex, 201, r);
                return;
            }
            // every other route needs a verified client certificate
            String san = null;
            try {
                var certs = ((HttpsExchange) ex).getSSLSession().getPeerCertificates();
                var c = (java.security.cert.X509Certificate) certs[0];
                var sans = c.getSubjectAlternativeNames();
                if (sans != null) for (var s : sans) san = String.valueOf(s.get(1));
            } catch (Exception e) {
                san = null;
            }
            if (san == null) {
                send(ex, 401, map("code", "mtls", "message", "client certificate required"));
                return;
            }
            clientSans.add(san);
            if (path.equals("/fleet/v1/heartbeat") && method.equals("POST")) {
                heartbeats.add((Map<String, Object>) Json.parsePlain(body, false));
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("next_heartbeat_s", 30L);
                r.put("kill", kill);
                r.put("min_issued_seq", minIssuedSeq);
                Map<String, Object> env = envelope;
                r.put("policy_current", env == null ? null : map("policy_id", env.get("policy_id"), "version", env.get("version"),
                    "issued_seq", env.get("issued_seq"), "hash", env.get("hash")));
                if (env == null) r.remove("policy_current");
                List<Object> add = addSigningKeys;
                List<Object> rev = revokeSigningKeys;
                if (add != null) r.put("add_signing_keys", add);
                if (rev != null) r.put("revoke_signing_keys", rev);
                send(ex, 200, r);
                return;
            }
            if (path.equals("/fleet/v1/policy") && method.equals("GET")) {
                policyFetches++;
                Map<String, Object> env = envelope;
                if (env == null) {
                    send(ex, 404, map("code", "none", "message", "no policy"));
                    return;
                }
                String etag = "\"" + env.get("hash") + "\"";
                if (etag.equals(ex.getRequestHeaders().getFirst("if-none-match"))) {
                    send(ex, 304, null);
                    return;
                }
                send(ex, 200, env, "etag", etag);
                return;
            }
            if (path.equals("/v1/logs") && method.equals("POST")) {
                if (failLogs > 0) {
                    failLogs--;
                    send(ex, 503, map("code", "busy"), "retry-after", "0");
                    return;
                }
                gzipSeen = String.valueOf(ex.getRequestHeaders().getFirst("content-encoding"));
                byte[] raw = body;
                if ("gzip".equals(ex.getRequestHeaders().getFirst("content-encoding"))) {
                    raw = new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(body)).readAllBytes();
                }
                Map<String, Object> doc = (Map<String, Object>) Json.parsePlain(raw, false);
                otlpRequests.add(doc);
                for (Object rl : (List<Object>) doc.get("resourceLogs")) {
                    for (Object sl : (List<Object>) ((Map<String, Object>) rl).get("scopeLogs")) {
                        for (Object lr : (List<Object>) ((Map<String, Object>) sl).get("logRecords")) {
                            String ev = (String) ((Map<String, Object>) ((Map<String, Object>) ((Map<String, Object>) lr).get("body"))).get("stringValue");
                            eventStrings.add(ev);
                            events.add((Map<String, Object>) Json.parsePlain(ev.getBytes(StandardCharsets.UTF_8), false));
                        }
                    }
                }
                send(ex, logsStatus, map());
                return;
            }
            send(ex, 404, map("code", "not_found", "message", "no route"));
        } catch (Exception e) {
            e.printStackTrace();
            send(ex, 500, map("code", "internal", "message", String.valueOf(e)));
        }
    }

    // --- helpers ----------------------------------------------------------------------------

    public boolean waitFor(Predicate<FakeCore> pred, long timeoutMs) throws InterruptedException {
        long t0 = System.currentTimeMillis();
        while (System.currentTimeMillis() - t0 < timeoutMs) {
            if (pred.test(this)) return true;
            Thread.sleep(25);
        }
        return pred.test(this);
    }

    public Map<String, Object> lastHeartbeat() {
        return heartbeats.isEmpty() ? Map.of() : heartbeats.get(heartbeats.size() - 1);
    }

    public String lastHeartbeatState() {
        return heartbeats.isEmpty() ? "" : String.valueOf(heartbeats.get(heartbeats.size() - 1).get("state"));
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
