package io.github.ivseb.traffictwin.fleet;

import io.github.ivseb.traffictwin.sanitizer.Json;
import io.github.ivseb.traffictwin.sanitizer.Json.Lex;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;

/**
 * Fleet API client (api/fleet-api.v1.openapi.yaml): enrollment with a {@code tte_} token and CA
 * pin, then mTLS calls for heartbeat and policy. Requests made here use a plain
 * {@link HttpClient}, so the capture integrations never see them.
 */
public final class FleetClient {
    public static final Pattern TOKEN = Pattern.compile("tte_[A-Za-z0-9_-]{32,128}\\.([A-Za-z0-9_-]{43})");

    /** Failure with a short code that is safe to report (never payload values). */
    public static final class FleetException extends Exception {
        private static final long serialVersionUID = 1L;
        private final String code;
        private final int status;

        public FleetException(String code, int status) {
            super(code, null, false, false);
            this.code = code;
            this.status = status;
        }

        public String code() {
            return code;
        }

        /** HTTP status, or -1. */
        public int status() {
            return status;
        }
    }

    public record SigningKey(String kid, String publicKey) {}

    /** Result of enrollment (fleet-api {@code Enrollment}) plus local bookkeeping. */
    public static final class Enrollment {
        public String sourceId = "";
        public String group = "";
        public String serviceName = "";
        public String clientCert = "";
        public String caChain = "";
        public String notAfter;
        public List<SigningKey> signingKeys = new ArrayList<>();
        public String intakeUrl = "";
        public String fleetUrl = "";
        public long policyMaxAgeS = 86400;
        public long heartbeatIntervalS = 30;
        public long policyPollIntervalS = 60;
        public String enrollUrl = "";
        public String pin = "";

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("source_id", sourceId);
            m.put("group", group);
            m.put("service_name", serviceName);
            m.put("client_cert", clientCert);
            m.put("ca_chain", caChain);
            if (notAfter != null) m.put("not_after", notAfter);
            List<Object> keys = new ArrayList<>();
            for (SigningKey k : signingKeys) keys.add(new LinkedHashMap<>(Map.of("kid", k.kid(), "alg", "Ed25519", "public_key", k.publicKey())));
            m.put("policy_signing_keys", keys);
            m.put("intake_url", intakeUrl);
            m.put("fleet_url", fleetUrl);
            m.put("policy_max_age_s", policyMaxAgeS);
            m.put("heartbeat_interval_s", heartbeatIntervalS);
            m.put("policy_poll_interval_s", policyPollIntervalS);
            m.put("enroll_url", enrollUrl);
            m.put("pin", pin);
            return m;
        }

        @SuppressWarnings("unchecked")
        public static Enrollment fromMap(Map<String, Object> m) {
            Enrollment e = new Enrollment();
            e.sourceId = s(m.get("source_id"));
            e.group = s(m.get("group"));
            e.serviceName = s(m.get("service_name"));
            e.clientCert = s(m.get("client_cert"));
            e.caChain = s(m.get("ca_chain"));
            e.notAfter = m.get("not_after") instanceof String n ? n : null;
            if (m.get("policy_signing_keys") instanceof List<?> l) {
                for (Object o : l) {
                    Map<String, Object> k = (Map<String, Object>) o;
                    e.signingKeys.add(new SigningKey(s(k.get("kid")), s(k.get("public_key"))));
                }
            }
            e.intakeUrl = s(m.get("intake_url"));
            e.fleetUrl = s(m.get("fleet_url"));
            e.policyMaxAgeS = n(m.get("policy_max_age_s"), 86400);
            e.heartbeatIntervalS = n(m.get("heartbeat_interval_s"), 30);
            e.policyPollIntervalS = n(m.get("policy_poll_interval_s"), 60);
            e.enrollUrl = s(m.get("enroll_url"));
            e.pin = s(m.get("pin"));
            return e;
        }

        private static String s(Object o) {
            return o instanceof String x ? x : "";
        }

        private static long n(Object o, long d) {
            return o instanceof Lex l ? (long) Double.parseDouble(l.lex) : d;
        }
    }

    /** Source identity sent at enrollment. */
    public record SourceInfo(String kind, String version, String serviceName, String instance, Map<String, Object> runtime, List<String> hmacKids) {
        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("kind", kind);
            m.put("version", version);
            m.put("service_name", serviceName);
            if (instance != null) m.put("instance", instance.length() > 128 ? instance.substring(0, 128) : instance);
            if (runtime != null) m.put("runtime", runtime);
            if (hmacKids != null && !hmacKids.isEmpty()) m.put("hmac_kids", new ArrayList<Object>(hmacKids.subList(0, Math.min(8, hmacKids.size()))));
            return m;
        }
    }

    /** HTTP response with the body already read (bounded). */
    public record Response(int status, Map<String, List<String>> headers, byte[] body) {
        public String header(String name) {
            for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                if (e.getKey().equalsIgnoreCase(name) && !e.getValue().isEmpty()) return e.getValue().get(0);
            }
            return null;
        }

        public Object json() {
            try {
                return Json.parsePlain(body, false);
            } catch (RuntimeException e) {
                return null;
            }
        }
    }

    public static String tokenPin(String token) {
        var m = TOKEN.matcher(token);
        return m.matches() ? m.group(1) : null;
    }

    private static boolean isHttps(String v) {
        try {
            return v != null && "https".equalsIgnoreCase(URI.create(v).getScheme());
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * One bounded HTTP exchange. The answer is read through a bounded subscriber: the read is abandoned (and the
     * connection cancelled) at {@code maxBody + 1} bytes, never buffered whole; a {@code gzip} answer is inflated
     * with the same bound. {@code timeout} limits the wait for the headers; the whole exchange, body included,
     * is limited to twice that (the JDK request timeout does not cover the body read).
     *
     * @throws IOException on a network error, a timeout or an answer beyond {@code maxBody}
     */
    public static Response send(HttpClient c, String method, URI uri, Map<String, String> headers, byte[] body, Duration timeout, int maxBody)
        throws IOException, InterruptedException {
        HttpRequest.Builder b = HttpRequest.newBuilder(uri).timeout(timeout);
        if (headers != null) headers.forEach(b::header);
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
        long totalMs = Math.max(1L, timeout.multipliedBy(2).toMillis());
        CompletableFuture<HttpResponse<byte[]>> f = c.sendAsync(b.build(), info -> {
            long declared = info.headers().firstValueAsLong("content-length").orElse(-1L);
            return new BoundedSubscriber(maxBody, declared > maxBody);
        });
        HttpResponse<byte[]> r;
        try {
            r = f.get(totalMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            f.cancel(true);
            throw new java.net.http.HttpTimeoutException("fleet_response_timeout");
        } catch (InterruptedException e) {
            f.cancel(true);
            throw e;
        } catch (ExecutionException e) {
            f.cancel(true);
            Throwable t = e.getCause();
            if (t instanceof IOException io) throw io;
            throw new IOException("fleet_request_failed", t);
        }
        byte[] rb = r.body();
        String enc = r.headers().firstValue("content-encoding").orElse("identity").trim().toLowerCase(java.util.Locale.ROOT);
        if (enc.equals("gzip") || enc.equals("x-gzip")) {
            rb = inflateBounded(rb, maxBody);
        } else if (!enc.isEmpty() && !enc.equals("identity")) {
            throw new IOException("fleet_response_encoding");
        }
        return new Response(r.statusCode(), r.headers().map(), rb);
    }

    private static byte[] inflateBounded(byte[] gz, int max) throws IOException {
        try (java.util.zip.GZIPInputStream in = new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(gz))) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(Math.min(max, 8192));
            byte[] buf = new byte[8192];
            int total = 0;
            for (int n; (n = in.read(buf)) > 0; ) {
                total += n;
                if (total > max) throw new IOException("fleet_response_too_large");
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }

    /** Collects at most {@code max} bytes; one more byte cancels the subscription and fails the exchange. */
    private static final class BoundedSubscriber implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        private final int max;
        private final boolean tooLarge;
        private Flow.Subscription subscription;
        private int total;
        private boolean finished;

        BoundedSubscriber(int max, boolean tooLarge) {
            this.max = max;
            this.tooLarge = tooLarge;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
        }

        @Override
        public void onSubscribe(Flow.Subscription s) {
            subscription = s;
            if (tooLarge) {
                finished = true;
                s.cancel();
                result.completeExceptionally(new IOException("fleet_response_too_large"));
                return;
            }
            s.request(1);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            if (finished) return;
            for (ByteBuffer bb : items) {
                int n = bb.remaining();
                if ((long) total + n > max) {
                    finished = true;
                    subscription.cancel();
                    result.completeExceptionally(new IOException("fleet_response_too_large"));
                    return;
                }
                byte[] chunk = new byte[n];
                bb.get(chunk);
                out.write(chunk, 0, n);
                total += n;
            }
            subscription.request(1);
        }

        @Override
        public void onError(Throwable t) {
            finished = true;
            result.completeExceptionally(t);
        }

        @Override
        public void onComplete() {
            if (!finished) {
                finished = true;
                result.complete(out.toByteArray());
            }
        }
    }

    public static HttpClient client(SSLContext ctx) {
        return HttpClient.newBuilder().sslContext(ctx).version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(10)).build();
    }

    /**
     * Enrolls with a token on the no-CSR path (the JDK has no public PKCS#10 API): tt-core
     * generates the key and returns it once over the pinned TLS channel; the caller stores it
     * in a 0600 PKCS#12 file and never again in clear.
     *
     * @return the enrollment and the private key (PKCS#8 PEM)
     */
    public static Object[] enroll(String enrollUrl, String token, SourceInfo source) throws FleetException {
        String pin = tokenPin(token);
        if (pin == null) throw new FleetException("enroll_token_malformed", -1);
        URI base;
        try {
            base = URI.create(enrollUrl);
        } catch (IllegalArgumentException e) {
            throw new FleetException("enroll_url_invalid", -1);
        }
        if (!"https".equalsIgnoreCase(base.getScheme()) || base.getHost() == null) throw new FleetException("enroll_url_not_https", -1);
        X509Certificate root = pinnedRoot(base, pin);
        Response res;
        try {
            SSLContext ctx = Pki.trustOnly(List.of(root));
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("token", token);
            body.put("source", source.toMap());
            res = send(client(ctx), "POST", base.resolve("/fleet/v1/enroll"), Map.of("content-type", "application/json"),
                Json.writeCanonical(body).getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(15), 1 << 20);
        } catch (IOException | GeneralSecurityException e) {
            throw new FleetException("enroll_network", -1);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new FleetException("enroll_interrupted", -1);
        }
        if (res.status() != 201 && res.status() != 200) throw new FleetException("enroll_http_" + res.status(), res.status());
        if (!(res.json() instanceof Map<?, ?>)) throw new FleetException("enroll_bad_response", -1);
        @SuppressWarnings("unchecked")
        Map<String, Object> j = (Map<String, Object>) res.json();
        if (!(j.get("client_key") instanceof String keyPem)) throw new FleetException("enroll_no_key", -1);
        Enrollment e = new Enrollment();
        e.sourceId = str(j.get("source_id"));
        e.group = str(j.get("group"));
        e.serviceName = str(j.get("service_name"));
        e.clientCert = str(j.get("client_cert"));
        e.caChain = str(j.get("ca_chain"));
        e.notAfter = j.get("not_after") instanceof String n ? n : null;
        if (j.get("policy_signing_keys") instanceof List<?> keys) {
            for (Object o : keys) {
                if (!(o instanceof Map<?, ?> km)) continue;
                Object kid = km.get("kid");
                Object pk = km.get("public_key");
                if (kid instanceof String ks && ks.matches("[A-Za-z0-9._-]{1,64}") && "Ed25519".equals(km.get("alg"))
                    && pk instanceof String ps && ps.matches("[A-Za-z0-9_-]{43}")) {
                    e.signingKeys.add(new SigningKey(ks, ps));
                }
            }
        }
        e.intakeUrl = str(j.get("intake_url"));
        e.fleetUrl = str(j.get("fleet_url"));
        e.policyMaxAgeS = num(j.get("policy_max_age_s"), 86400);
        e.heartbeatIntervalS = num(j.get("heartbeat_interval_s"), 30);
        e.policyPollIntervalS = num(j.get("policy_poll_interval_s"), 60);
        e.enrollUrl = enrollUrl;
        e.pin = pin;
        if (!e.sourceId.matches("src-[0-9A-Za-z]{1,32}")) throw new FleetException("enroll_bad_source_id", -1);
        if (!e.group.matches("[a-z0-9][a-z0-9-]{0,62}")) throw new FleetException("enroll_bad_group", -1);
        if (!e.serviceName.matches("[a-z0-9][a-z0-9._-]{0,62}")) throw new FleetException("enroll_bad_service_name", -1);
        if (Pki.pemBlocks(e.clientCert, "CERTIFICATE").isEmpty()) throw new FleetException("enroll_bad_cert", -1);
        boolean pinned = false;
        for (byte[] der : Pki.pemBlocks(e.caChain, "CERTIFICATE")) if (Pki.pinOf(der).equals(pin)) pinned = true;
        if (!pinned) throw new FleetException("enroll_chain_without_pinned_root", -1);
        if (e.signingKeys.isEmpty()) throw new FleetException("enroll_no_signing_keys", -1);
        if (!isHttps(e.intakeUrl) || !isHttps(e.fleetUrl)) throw new FleetException("enroll_bad_urls", -1);
        return new Object[] {e, keyPem};
    }

    /** Presented chain's root must match the pin; the root is then the only trust anchor. */
    private static X509Certificate pinnedRoot(URI base, String pin) throws FleetException {
        List<X509Certificate> chain;
        try {
            chain = Pki.presentedChain(base, 10_000);
        } catch (IOException | GeneralSecurityException e) {
            throw new FleetException("enroll_tls_error", -1);
        }
        for (X509Certificate c : chain) {
            if (!c.getSubjectX500Principal().equals(c.getIssuerX500Principal()) || c.getBasicConstraints() < 0) continue;
            try {
                if (Pki.pinOf(c.getEncoded()).equals(pin)) return c;
            } catch (GeneralSecurityException e) {
                // try the next one
            }
        }
        boolean hasRoot = false;
        for (X509Certificate c : chain) if (c.getSubjectX500Principal().equals(c.getIssuerX500Principal())) hasRoot = true;
        throw new FleetException(hasRoot ? "enroll_pin_mismatch" : "enroll_root_missing", -1);
    }

    private static String str(Object o) {
        return o instanceof String s ? s : "";
    }

    private static long num(Object o, long d) {
        return o instanceof Lex l ? (long) Double.parseDouble(l.lex) : d;
    }

    // ---------------------------------------------------------------------------------
    // mTLS calls

    private final HttpClient http;
    private final String fleetUrl;

    public FleetClient(Enrollment e, HttpClient mtlsClient) {
        this.http = mtlsClient;
        this.fleetUrl = e.fleetUrl;
    }

    private URI url(String path) {
        return URI.create(fleetUrl).resolve(path);
    }

    public Response heartbeat(Map<String, Object> body) throws IOException, InterruptedException {
        return send(http, "POST", url("/fleet/v1/heartbeat"), Map.of("content-type", "application/json"),
            Json.writeCanonical(body).getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(10), 1 << 20);
    }

    public Response getPolicy(String etag) throws IOException, InterruptedException {
        Map<String, String> h = etag == null ? Map.of() : Map.of("if-none-match", etag);
        return send(http, "GET", url("/fleet/v1/policy"), h, null, Duration.ofSeconds(10), 8 << 20);
    }

    /** Certificate renewal on the no-CSR path; the response carries a new key. */
    public Response renew() throws IOException, InterruptedException {
        return send(http, "POST", url("/fleet/v1/renew"), Map.of("content-type", "application/json"), "{}".getBytes(StandardCharsets.UTF_8),
            Duration.ofSeconds(10), 1 << 20);
    }
}
