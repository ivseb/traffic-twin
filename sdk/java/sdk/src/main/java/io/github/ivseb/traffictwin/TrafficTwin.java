package io.github.ivseb.traffictwin;

import io.github.ivseb.traffictwin.capture.RawExchange;
import io.github.ivseb.traffictwin.export.EventBuilder;
import io.github.ivseb.traffictwin.export.Exporter;
import io.github.ivseb.traffictwin.fleet.FleetClient;
import io.github.ivseb.traffictwin.fleet.FleetClient.Enrollment;
import io.github.ivseb.traffictwin.fleet.FleetClient.FleetException;
import io.github.ivseb.traffictwin.fleet.FleetClient.Response;
import io.github.ivseb.traffictwin.fleet.FleetClient.SigningKey;
import io.github.ivseb.traffictwin.fleet.Pki;
import io.github.ivseb.traffictwin.fleet.StateStore;
import io.github.ivseb.traffictwin.sanitizer.Base64Url;
import io.github.ivseb.traffictwin.sanitizer.Ed25519;
import io.github.ivseb.traffictwin.sanitizer.Envelope;
import io.github.ivseb.traffictwin.sanitizer.Json;
import io.github.ivseb.traffictwin.sanitizer.Json.Lex;
import io.github.ivseb.traffictwin.sanitizer.KeyRing;
import io.github.ivseb.traffictwin.sanitizer.KeyRing.KeyRef;
import io.github.ivseb.traffictwin.sanitizer.Policy;
import io.github.ivseb.traffictwin.sanitizer.Refused;
import io.github.ivseb.traffictwin.sanitizer.Sanitizer;
import io.github.ivseb.traffictwin.sanitizer.Utf8;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The agent: Fleet lifecycle (policy.md 4, fleet-api), capture gate, asynchronous sanitization and
 * export. Fail-closed everywhere: any doubt means "do not capture". It never touches the
 * application's global state (no {@code GlobalOpenTelemetry}, no default {@code SSLContext}, no
 * {@code Authenticator}).
 */
public final class TrafficTwin {
    /** Heartbeat states (fleet-api {@code Heartbeat.state}). */
    public static final String CAPTURING = "capturing";

    private static final int PENDING_MAX = 2000;
    private static final long PENDING_MAX_BYTES = 64L << 20;
    private static volatile TrafficTwin current;

    /** The running agent, or null. Cheap: a volatile read. */
    public static TrafficTwin current() {
        return current;
    }

    /** Starts the agent (idempotent: one per JVM). Returns immediately; Fleet work happens in the background. Never throws. */
    public static synchronized TrafficTwin start(Config cfg) {
        if (current != null) return current;
        TrafficTwin t = new TrafficTwin(cfg);
        current = t;
        t.begin();
        return t;
    }

    /** Starts from {@code TT_*} environment variables; null when TT_DISABLED is set. */
    public static TrafficTwin startFromEnvironment() {
        if (Config.disabled(System.getenv())) return null;
        return start(Config.fromEnvironment());
    }

    // ---------------------------------------------------------------------------------

    public final Config cfg;
    public final Exporter.Counters counters = new Exporter.Counters();
    private final Object lock = new Object();

    private volatile String state = "starting";
    private volatile Sanitizer san;
    private volatile Set<String> decisionNames = Set.of("baggage");
    private volatile String serviceName = "";
    private volatile Policy policy;
    private volatile Enrollment enrollment;

    private String policyKid = "";
    private String rejected;
    // A heartbeat said a newer policy is current (a normal policy change): capture pauses until it
    // is fetched, and only a failed fetch is an error (policy.md 4).
    private boolean switching;
    private KeyRing ring;
    private boolean heartbeatOk;
    private long lastContactMs;
    private Integer overrideBp;
    private String etag;
    // persisted
    private boolean kill;
    private boolean revoked;
    private long minIssuedSeq;
    private long lastIssuedSeq;
    private final Set<String> revokedKids = new HashSet<>();
    private final List<SigningKey> addedKeys = new ArrayList<>();

    private StateStore store;
    private HttpClient mtls;
    private FleetClient fleet;
    private Exporter exporter;
    private final ArrayDeque<String[]> lastErrors = new ArrayDeque<>();
    private final long[] overhead = new long[1024];
    private final AtomicLong overheadN = new AtomicLong();
    private final AtomicLong pendingBytes = new AtomicLong();
    private final CompletableFuture<Void> ready = new CompletableFuture<>();
    private volatile boolean stopped;
    /** Kill-switch generation: bumped by dropQueues(); an exchange sanitized across a bump is never enqueued. */
    private final java.util.concurrent.atomic.AtomicLong killGen = new java.util.concurrent.atomic.AtomicLong();

    private final ScheduledThreadPoolExecutor fleetExec;
    private final ThreadPoolExecutor sanitizeExec;

    private TrafficTwin(Config cfg) {
        this.cfg = cfg;
        fleetExec = new ScheduledThreadPoolExecutor(1, r -> daemon(r, "tt-fleet"));
        fleetExec.setRemoveOnCancelPolicy(true);
        sanitizeExec = new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(PENDING_MAX), r -> daemon(r, "tt-sanitize"),
            (r, ex) -> {
                counters.eventsDroppedQueue.incrementAndGet();
                if (r instanceof Job j) pendingBytes.addAndGet(-j.raw.heldBytes);
            });
    }

    private static Thread daemon(Runnable r, String name) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        return t;
    }

    private static final class Job implements Runnable {
        final RawExchange raw;
        final TrafficTwin tt;

        Job(TrafficTwin tt, RawExchange raw) {
            this.tt = tt;
            this.raw = raw;
        }

        @Override
        public void run() {
            tt.pendingBytes.addAndGet(-raw.heldBytes);
            tt.process(raw);
        }
    }

    // --- hot path (must be cheap and never throw) ---------------------------------------

    /** The sanitizer when capture is allowed, else null. */
    public Sanitizer active() {
        return san;
    }

    public String serviceName() {
        return serviceName;
    }

    /** Header names (lowercase) needed for the inbound sampling decision. */
    public Set<String> decisionHeaders() {
        return decisionNames;
    }

    /** Whether tt.s may be added to the baggage of a call to this url base (sanitizer.md 12). */
    public boolean mayPropagate(String urlBase) {
        Policy p = policy;
        if (p == null || p.propagateTo.isEmpty()) return false;
        String hostport = hostPort(urlBase);
        if (hostport == null) return false;
        String host = hostport.replaceFirst(":[0-9]+$", "");
        // D-M8: never toward a host that matches a policy base (external service).
        if (p.baseHosts.contains(hostport) || p.baseHosts.contains(host)) return false;
        return p.propagateTo.contains(hostport) || p.propagateTo.contains(host);
    }

    private static String hostPort(String urlBase) {
        try {
            URI u = URI.create(urlBase);
            if (u.getHost() == null) return null;
            String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(java.util.Locale.ROOT);
            int port = u.getPort();
            if ((scheme.equals("http") && port == 80) || (scheme.equals("https") && port == 443)) port = -1;
            String h = u.getHost().toLowerCase(java.util.Locale.ROOT);
            return port > 0 ? h + ":" + port : h;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public void noteSeen() {
        counters.exchangesSeen.incrementAndGet();
    }

    public void noteSampled() {
        counters.exchangesSampled.incrementAndGet();
    }

    public void noteOverhead(long ns) {
        overhead[(int) (overheadN.getAndIncrement() & (overhead.length - 1))] = ns;
    }

    public void noteError(String code) {
        String c = code.length() > 64 ? code.substring(0, 64) : code;
        synchronized (lastErrors) {
            lastErrors.addLast(new String[] {c, Instant.now().toString()});
            while (lastErrors.size() > 20) lastErrors.removeFirst();
        }
        if (cfg.debug) System.err.println("[traffic-twin] error " + c);
    }

    /** Queues a finished exchange for asynchronous sanitization. Drops it (and counts it) if the queue is full. */
    public void submit(RawExchange raw) {
        if (san == null || pendingBytes.get() + raw.heldBytes > PENDING_MAX_BYTES) {
            counters.eventsDroppedQueue.incrementAndGet();
            return;
        }
        pendingBytes.addAndGet(raw.heldBytes);
        try {
            sanitizeExec.execute(new Job(this, raw));
        } catch (RejectedExecutionException e) {
            pendingBytes.addAndGet(-raw.heldBytes);
            counters.eventsDroppedQueue.incrementAndGet();
        }
    }

    private void process(RawExchange raw) {
        Exporter ex = exporter;
        Enrollment en = enrollment;
        if (ex == null || en == null || san == null) return;
        long gen = killGen.get();
        try {
            Sanitizer.Result r = raw.sanitizer.run(raw.build.get(), System.currentTimeMillis(), raw.decision);
            if (r.outcome.equals("not_sampled")) return;
            if (r.outcome.equals("too_large")) {
                counters.sanitizerErrors.incrementAndGet();
                noteError("event_too_large");
                return;
            }
            Policy p = raw.sanitizer.policy;
            EventBuilder.Meta m = new EventBuilder.Meta();
            m.policyId = p.policyId;
            m.policyVersion = p.version;
            m.policyHash = p.hash;
            m.sourceId = en.sourceId;
            m.inbound = raw.inbound;
            m.tsMs = raw.tsMs;
            m.latencyMs = raw.latencyMs;
            m.status = raw.status;
            m.netError = raw.netError;
            m.traceId = raw.traceId;
            m.spanId = raw.spanId;
            m.parentSpanId = raw.parentSpanId;
            String json = EventBuilder.buildEvent(r.parts, m);
            if (json == null) {
                counters.sanitizerErrors.incrementAndGet();
                noteError("event_invalid_or_too_large");
                return;
            }
            if (gen != killGen.get() || san == null) { // the kill switch arrived while this exchange was being sanitized
                counters.eventsDroppedQueue.incrementAndGet();
                return;
            }
            ex.enqueue(new EventBuilder.Queued(json, raw.tsMs, raw.traceId, raw.spanId, p.hash), ex.generation());
        } catch (RuntimeException | StackOverflowError e) {
            // An internal error never produces an event (sanitizer.md introduction).
            counters.sanitizerErrors.incrementAndGet();
            noteError("sanitizer_error");
        }
    }

    // --- lifecycle --------------------------------------------------------------------

    private void begin() {
        fleetExec.execute(() -> {
            try {
                bootstrap();
            } catch (RuntimeException | LinkageError e) {
                // A LinkageError means the SDK classes cannot be linked here (class loader layout): fail closed.
                noteError("start_failed");
                if (cfg.debug) System.err.println("[traffic-twin] start failed: " + e);
            } finally {
                recompute();
                ready.complete(null);
            }
        });
    }

    /** Completes when the first Fleet cycle (enrollment, heartbeat, policy) has finished, successfully or not. */
    public CompletableFuture<Void> ready() {
        return ready;
    }

    public String state() {
        return state;
    }

    /** Current policy, or null. */
    public Policy policy() {
        return policy;
    }

    public Enrollment enrollment() {
        return enrollment;
    }

    /** Stops the agent: no more capture, no more traffic of its own. */
    public void stop() {
        stopped = true;
        san = null;
        fleetExec.shutdownNow();
        sanitizeExec.shutdownNow();
        Exporter e = exporter;
        if (e != null) e.stop();
        synchronized (TrafficTwin.class) {
            if (current == this) current = null;
        }
    }

    /** Sanitizes what is pending and sends everything queued (tests, graceful shutdown). */
    public void flush() {
        try {
            sanitizeExec.submit(() -> {}).get(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            // best effort
        }
        Exporter e = exporter;
        if (e != null) e.flush();
    }

    private void bootstrap() {
        String svc = cfg.serviceName;
        if (cfg.enrollUrl == null || svc == null) {
            noteError("not_configured");
            return;
        }
        store = new StateStore(cfg.stateDir != null ? cfg.stateDir : StateStore.defaultDir(cfg.enrollUrl, svc), this::noteError);
        if (!store.prepare()) {
            // A state directory we cannot trust (owned by another user, a symlink, cannot be made 0700): never read
            // from it. The state then lives in a private temporary directory and the enrollment does not survive a restart.
            noteError("state_dir_untrusted");
            try {
                store = new StateStore(Files.createTempDirectory("traffic-twin-"), this::noteError);
            } catch (IOException | RuntimeException e) {
                noteError("state_dir_unavailable");
                return;
            }
        }
        loadPersisted();
        loadKeys();
        Map<String, Object> saved = store.readJson("enrollment.json");
        byte[] p12 = store.readBytes("client.p12");
        String envPass = System.getenv("TT_KEYSTORE_PASSWORD");
        String pass = envPass != null && !envPass.isEmpty() ? envPass : store.readText("keystore.pass");
        boolean reused = false;
        if (saved != null && p12 != null && pass != null && cfg.enrollUrl.equals(saved.get("enroll_url"))) {
            try {
                enrollment = Enrollment.fromMap(saved);
                connect(loadKeyStore(p12, pass.toCharArray()), pass.toCharArray());
                reused = true;
            } catch (GeneralSecurityException | IOException | RuntimeException e) {
                noteError("state_invalid");
                enrollment = null;
            }
        }
        if (!reused) {
            enrollWithRetry();
            if (enrollment == null) return;
        }
        // Re-verify the cached policy (its issued_seq may equal the last accepted one).
        String cached = store.readText("policy.envelope.json");
        if (cached != null) {
            try {
                tryAccept(Json.parsePlain(cached.getBytes(StandardCharsets.UTF_8), true), true, cached);
            } catch (RuntimeException e) {
                noteError("policy_cache_invalid");
            }
        }
        heartbeat();
        pollPolicy();
        schedule();
    }

    private static KeyStore loadKeyStore(byte[] p12, char[] pass) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(p12), pass);
        return ks;
    }

    private void enrollWithRetry() {
        if (cfg.enrollToken == null) {
            noteError("enroll_token_missing");
            return;
        }
        long delay = 2000;
        for (int attempt = 0; attempt < 8 && !stopped; attempt++) {
            try {
                Map<String, Object> rt = new LinkedHashMap<>();
                rt.put("lang", "java");
                rt.put("lang_version", System.getProperty("java.version", ""));
                rt.put("os", System.getProperty("os.name", ""));
                rt.put("arch", System.getProperty("os.arch", ""));
                String instance = cfg.instance != null ? cfg.instance : hostName();
                Object[] r = FleetClient.enroll(cfg.enrollUrl, cfg.enrollToken,
                    new FleetClient.SourceInfo(Version.SOURCE_KIND, Version.SDK_VERSION, cfg.serviceName, instance, rt,
                        ring == null ? null : ring.kids()));
                Enrollment e = (Enrollment) r[0];
                String keyPem = (String) r[1];
                persistIdentity(e, keyPem);
                return;
            } catch (FleetException e) {
                noteError(e.code());
                // Token or identity errors will not fix themselves.
                if (e.status() >= 0 && e.status() < 500) return;
                if (e.code().matches(".*(pin|root|token|chain|bad_).*")) return;
            } catch (GeneralSecurityException | IOException | RuntimeException e) {
                noteError("enroll_failed");
            }
            try {
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            delay = Math.min(delay * 2, 300_000);
        }
    }

    private static String hostName() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (IOException e) {
            return "unknown";
        }
    }

    /** Stores the key received once in a 0600 PKCS#12 file and connects. The PEM never touches the disk. */
    private void persistIdentity(Enrollment e, String keyPem) throws GeneralSecurityException, IOException {
        PrivateKey key = Pki.parsePrivateKey(keyPem);
        List<X509Certificate> chain = new ArrayList<>(Pki.parseCerts(e.clientCert));
        for (X509Certificate c : Pki.parseCerts(e.caChain)) {
            if (!c.getSubjectX500Principal().equals(c.getIssuerX500Principal())) chain.add(c);
        }
        String pass = System.getenv("TT_KEYSTORE_PASSWORD");
        if (pass == null || pass.isEmpty()) {
            byte[] r = new byte[24];
            new SecureRandom().nextBytes(r);
            pass = Base64Url.encode(r);
        }
        KeyStore ks = Pki.keyStore(key, chain, pass.toCharArray());
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        ks.store(bo, pass.toCharArray());
        store.writeBytes("client.p12", bo.toByteArray());
        // With TT_KEYSTORE_PASSWORD the password is never written; otherwise it sits next to client.p12 and both
        // are protected by the 0700 directory + 0600 files + ownership checks (see StateStore), not by the password.
        String envPass = System.getenv("TT_KEYSTORE_PASSWORD");
        if (envPass == null || envPass.isEmpty()) store.writeText("keystore.pass", pass);
        else store.remove("keystore.pass");
        store.writeJson("enrollment.json", e.toMap());
        enrollment = e;
        connect(ks, pass.toCharArray());
    }

    private void connect(KeyStore ks, char[] pass) throws GeneralSecurityException, IOException {
        Enrollment e = enrollment;
        List<X509Certificate> anchors = Pki.parseCerts(e.caChain);
        mtls = FleetClient.client(Pki.mtls(ks, pass, anchors));
        serviceName = e.serviceName;
        if (fleet == null) fleet = new FleetClient(e, mtls);
        else fleet = new FleetClient(e, mtls);
        URI intake = URI.create(e.intakeUrl);
        if (exporter != null) exporter.setTarget(intake, mtls);
        else exporter = new Exporter(mtls, intake, e.serviceName, e.sourceId, counters, this::noteError, cfg.exportFlushMs,
            10_000, 16L << 20, 5, 1000, 30_000, cfg.gzip);
    }

    private void schedule() {
        Enrollment e = enrollment;
        long hb = cfg.heartbeatIntervalMs > 0 ? cfg.heartbeatIntervalMs : Math.max(5, e.heartbeatIntervalS) * 1000;
        long pp = cfg.policyPollIntervalMs > 0 ? cfg.policyPollIntervalMs : Math.max(5, e.policyPollIntervalS) * 1000;
        fleetExec.scheduleWithFixedDelay(() -> guarded(this::heartbeat), hb, hb, TimeUnit.MILLISECONDS);
        fleetExec.scheduleWithFixedDelay(() -> guarded(this::pollPolicy), pp, pp, TimeUnit.MILLISECONDS);
    }

    /**
     * Runs a periodic task so that nothing it throws cancels the schedule (a {@code ScheduledThreadPoolExecutor}
     * suppresses every later run of a task that threw): the SDK never breaks the application and keeps polling.
     * Every {@code Throwable} is swallowed and counted, including {@link OutOfMemoryError} and
     * {@link StackOverflowError} (the task's own allocations are released when it unwinds, and a source that
     * stops polling would stop applying closing policies and the kill switch); {@link ThreadDeath} and
     * {@link LinkageError} are swallowed too. The JVM's fatal-error handling ({@code -XX:+ExitOnOutOfMemoryError})
     * is not bypassed: it acts before the exception reaches this code.
     */
    private void guarded(Runnable r) {
        try {
            r.run();
        } catch (Throwable t) {
            try {
                noteError("fleet_task_failed");
            } catch (Throwable ignored) {
                // out of memory while reporting: the next run reports again
            }
        }
    }

    // --- keys and persisted state ------------------------------------------------------

    private void loadKeys() {
        String text = cfg.hmacKey;
        if (text == null && cfg.hmacKeyFile != null) {
            try {
                text = Files.readString(cfg.hmacKeyFile, StandardCharsets.UTF_8);
            } catch (IOException e) {
                text = null;
            }
        }
        try {
            ring = KeyRing.parse(text);
        } catch (Refused r) {
            ring = null;
        }
    }

    /** The trusted policy signing keys: enrollment keys plus endorsed additions, minus revoked kids. */
    private Map<String, PublicKey> signingKeys() {
        Map<String, PublicKey> m = new HashMap<>();
        for (SigningKey k : pinnedKeys().values()) {
            PublicKey pk = Ed25519.publicKey(k.publicKey());
            if (pk != null) m.put(k.kid(), pk);
        }
        return m;
    }

    /** kid -> pinned key (first binding wins: enrollment before additions); revoked kids excluded. */
    private Map<String, SigningKey> pinnedKeys() {
        Map<String, SigningKey> m = new LinkedHashMap<>();
        Enrollment e = enrollment;
        List<SigningKey> all = new ArrayList<>();
        if (e != null) all.addAll(e.signingKeys);
        all.addAll(addedKeys);
        for (SigningKey k : all) {
            if (revokedKids.contains(k.kid()) || m.containsKey(k.kid())) continue;
            m.put(k.kid(), k);
        }
        return m;
    }

    @SuppressWarnings("unchecked")
    private void loadPersisted() {
        Map<String, Object> m = store.readJson("state.json");
        if (m == null) return;
        kill = Boolean.TRUE.equals(m.get("kill"));
        revoked = Boolean.TRUE.equals(m.get("revoked"));
        minIssuedSeq = longOf(m.get("min_issued_seq"));
        lastIssuedSeq = longOf(m.get("last_issued_seq"));
        if (m.get("revoked_kids") instanceof List<?> l) for (Object o : l) if (o instanceof String s) revokedKids.add(s);
        if (m.get("added_keys") instanceof List<?> l) {
            for (Object o : l) {
                if (o instanceof Map<?, ?> k && k.get("kid") instanceof String kid && k.get("public_key") instanceof String pk) addedKeys.add(new SigningKey(kid, pk));
            }
        }
    }

    private static long longOf(Object o) {
        return o instanceof Lex l ? (long) Double.parseDouble(l.lex) : 0;
    }

    private void persist() {
        if (store == null) return;
        try {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("kill", kill);
            m.put("revoked", revoked);
            m.put("min_issued_seq", minIssuedSeq);
            m.put("last_issued_seq", lastIssuedSeq);
            m.put("revoked_kids", new ArrayList<Object>(new java.util.TreeSet<>(revokedKids)));
            List<Object> ak = new ArrayList<>();
            for (SigningKey k : addedKeys) ak.add(new LinkedHashMap<>(Map.of("kid", k.kid(), "public_key", k.publicKey())));
            m.put("added_keys", ak);
            store.writeJson("state.json", m);
        } catch (IOException e) {
            noteError("state_write_failed");
        }
    }

    // --- policy (policy.md 4) -----------------------------------------------------------

    private void tryAccept(Object envelope, boolean fromCache, String rawText) {
        synchronized (lock) {
            try {
                Envelope.Verified v = Envelope.verify(envelope, signingKeys(), true);
                Policy p = new Policy(v.body());
                p.hash = v.hash();
                Policy cur = policy;
                if (cur != null && cur.hash.equals(p.hash) && !fromCache) return;
                Envelope.checkAcceptance(p, enrollment.group, System.currentTimeMillis(), lastIssuedSeq, minIssuedSeq, fromCache);
                if (switching && cfg.debug) System.err.println("[traffic-twin] info policy_changed: now issued_seq " + p.issuedSeq);
                policy = p;
                Object sig = ((Map<?, ?>) envelope).get("signature");
                policyKid = sig instanceof Map<?, ?> sm && sm.get("kid") instanceof String k ? k : "";
                rejected = null;
                switching = false;
                lastIssuedSeq = p.issuedSeq;
                persist();
                // The cache holds the signed envelope exactly as received; it is re-verified at start.
                if (!fromCache && store != null) {
                    try {
                        store.writeText("policy.envelope.json", rawText);
                    } catch (IOException e) {
                        noteError("state_write_failed");
                    }
                }
                Set<String> names = new HashSet<>(Set.of("baggage"));
                if (p.subject != null) names.add(p.subject.from().equals("header") ? Utf8.asciiLower(p.subject.name()) : "cookie");
                decisionNames = Collections.unmodifiableSet(names);
            } catch (Refused r) {
                // hardening.md 2.2: a policy refused for the safety subset is reported as policy_unsafe.
                noteError(r.isUnsafe() ? "policy_unsafe" : r.code());
                // Keep the previous policy if it is still valid; otherwise report the rejection.
                if (policy == null) rejected = r.code().equals("expired_policy") ? "expired_policy" : "policy_rejected";
            } catch (RuntimeException e) {
                noteError("policy_rejected");
                if (policy == null) rejected = "policy_rejected";
            }
            recompute();
        }
    }

    private void pollPolicy() {
        FleetClient f = fleet;
        if (f == null || stopped) return;
        try {
            Response r = f.getPolicy(policy != null ? etag : null);
            if (r.status() == 304) {
                lastContactMs = System.currentTimeMillis();
            } else if (r.status() == 200) {
                lastContactMs = System.currentTimeMillis();
                Object env;
                try {
                    env = Json.parsePlain(r.body(), true);
                } catch (RuntimeException e) {
                    noteError("policy_json");
                    synchronized (lock) {
                        if (policy == null) rejected = "policy_rejected";
                        recompute();
                    }
                    return;
                }
                tryAccept(env, false, new String(r.body(), StandardCharsets.UTF_8));
                if (policy != null && r.header("etag") != null) etag = r.header("etag");
            } else if (r.status() == 404) {
                lastContactMs = System.currentTimeMillis();
                synchronized (lock) {
                    policy = null;
                    rejected = "no_policy";
                }
            } else if (r.status() == 403) {
                revoke();
            } else {
                noteError("policy_http_" + r.status());
            }
        } catch (IOException e) {
            noteError("policy_network");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        synchronized (lock) {
            if (switching && policy == null) {
                // The newer policy announced by the heartbeat could not be fetched or accepted.
                switching = false;
                if ("starting".equals(rejected)) {
                    rejected = "policy_rejected";
                    noteError("policy_below_min_issued_seq");
                }
            }
            recompute();
        }
    }

    // --- heartbeat --------------------------------------------------------------------

    private Map<String, Object> overheadUs() {
        int n = (int) Math.min(overheadN.get(), overhead.length);
        Map<String, Object> m = new LinkedHashMap<>();
        if (n == 0) {
            m.put("p50", 0L);
            m.put("p99", 0L);
            return m;
        }
        long[] a = java.util.Arrays.copyOf(overhead, n);
        java.util.Arrays.sort(a);
        m.put("p50", Math.round(a[Math.min(n - 1, (int) Math.floor(0.5 * n))] / 1000.0));
        m.put("p99", Math.round(a[Math.min(n - 1, (int) Math.floor(0.99 * n))] / 1000.0));
        return m;
    }

    private void heartbeat() {
        FleetClient f = fleet;
        if (f == null || stopped) return;
        Map<String, Object> body;
        synchronized (lock) {
            loadKeys();
            recompute();
            Policy p = policy;
            body = new LinkedHashMap<>();
            body.put("source_id", enrollment.sourceId);
            body.put("state", state);
            if (p != null) {
                Map<String, Object> pm = new LinkedHashMap<>();
                pm.put("id", p.policyId);
                pm.put("version", p.version);
                pm.put("issued_seq", p.issuedSeq);
                pm.put("hash", p.hash);
                body.put("policy", pm);
            }
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("exchanges_seen", counters.exchangesSeen.get());
            c.put("exchanges_sampled", counters.exchangesSampled.get());
            c.put("events_sent", counters.eventsSent.get());
            c.put("events_dropped_queue", counters.eventsDroppedQueue.get());
            c.put("events_rejected", counters.eventsRejected.get());
            c.put("send_errors", counters.sendErrors.get());
            c.put("sanitizer_errors", counters.sanitizerErrors.get());
            body.put("counters", c);
            body.put("overhead_us", overheadUs());
            Map<String, Object> q = new LinkedHashMap<>();
            Exporter ex = exporter;
            q.put("events", (long) (ex == null ? 0 : ex.size()));
            q.put("bytes", ex == null ? 0L : ex.sizeBytes());
            body.put("queue", q);
            List<Object> errs = new ArrayList<>();
            synchronized (lastErrors) {
                for (String[] e : lastErrors) errs.add(new LinkedHashMap<>(Map.of("code", e[0], "at", e[1])));
            }
            body.put("last_errors", errs);
            body.put("runtime", new LinkedHashMap<>(Map.of("lang", "java", "lang_version", System.getProperty("java.version", ""))));
            // The kids this source trusts now: tt-core uses them to confirm a rotation arrived before a revocation.
            body.put("signing_kids", new ArrayList<Object>(new java.util.TreeSet<>(signingKeys().keySet())));
        }
        try {
            Response r = f.heartbeat(body);
            if (r.status() == 403) revoke();
            else if (r.status() == 200 && r.json() instanceof Map<?, ?> m) {
                @SuppressWarnings("unchecked")
                Map<String, Object> j = (Map<String, Object>) m;
                applyHeartbeat(j);
            } else noteError("heartbeat_http_" + r.status());
        } catch (IOException e) {
            noteError("heartbeat_network");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        synchronized (lock) {
            recompute();
        }
    }

    private void applyHeartbeat(Map<String, Object> j) {
        boolean pollNow = false;
        boolean renewNow = false;
        synchronized (lock) {
            heartbeatOk = true;
            lastContactMs = System.currentTimeMillis();
            boolean k = Boolean.TRUE.equals(j.get("kill"));
            if (k != kill) {
                kill = k;
                persist();
            }
            if (k) dropQueues();
            if (j.get("min_issued_seq") instanceof Lex l && Json.isIntLexeme(l.lex) && Double.parseDouble(l.lex) >= 0) {
                long v = (long) Double.parseDouble(l.lex);
                if (v != minIssuedSeq) {
                    minIssuedSeq = v;
                    persist();
                }
                if (policy != null && policy.issuedSeq < v) {
                    boolean newer = j.get("policy_current") instanceof Map<?, ?> pc && pc.get("hash") instanceof String ph && !ph.equals(policy.hash)
                            && pc.get("issued_seq") instanceof Lex sl && Json.isIntLexeme(sl.lex) && Double.parseDouble(sl.lex) >= v;
                    // The policy in use is superseded for good: capture stops at once (fail-closed).
                    policy = null;
                    if (newer) {
                        // A normal policy change: the newer policy is fetched right away (policy_current below).
                        switching = true;
                        rejected = "starting";
                        if (cfg.debug) System.err.println("[traffic-twin] info policy_superseded: fetching the newer policy");
                    } else {
                        rejected = "policy_rejected";
                        noteError("policy_below_min_issued_seq");
                    }
                    recompute();
                }
            }
            Object o = j.get("sampling_override_bp");
            if (o instanceof Lex l && Json.isIntLexeme(l.lex) && Double.parseDouble(l.lex) >= 0 && Double.parseDouble(l.lex) <= 10000) {
                overrideBp = (int) Double.parseDouble(l.lex);
            } else overrideBp = null;
            // Revocations first: they only remove trust, and a key endorsed by a kid revoked in this
            // very response must not be pinned.
            boolean keysChanged = false;
            if (j.get("revoke_signing_keys") instanceof List<?> l) {
                for (Object x : l) {
                    if (x instanceof String s && revokedKids.add(s)) {
                        addedKeys.removeIf(key -> key.kid().equals(s));
                        keysChanged = true;
                    }
                }
                if (policy != null && revokedKids.contains(policyKid)) {
                    policy = null;
                    rejected = "policy_rejected";
                    noteError("policy_key_revoked");
                }
            }
            if (j.get("add_signing_keys") instanceof List<?> l && addSigningKeys(l)) keysChanged = true;
            if (keysChanged) persist();
            if (j.get("policy_current") instanceof Map<?, ?> cur && cur.get("hash") instanceof String h && (policy == null || !h.equals(policy.hash))) pollNow = true;
            if (j.get("renew_before") instanceof String rb) {
                try {
                    if (System.currentTimeMillis() >= Instant.parse(rb).toEpochMilli()) renewNow = true;
                } catch (RuntimeException e) {
                    // malformed: ignore
                }
            }
        }
        if (pollNow) fleetExec.execute(() -> guarded(this::pollPolicy));
        if (renewNow) fleetExec.execute(() -> guarded(this::renew));
    }

    /**
     * Pins the endorsed keys of a heartbeat, in order (an endorser precedes the keys it endorses).
     * tt-core repeats every endorsed key at every heartbeat: a kid already pinned to the same key is
     * skipped silently. A revoked kid is never re-pinned, a kid is never re-bound to another key, and
     * the endorser must be pinned and not revoked. Called with revocations already applied.
     *
     * @return whether a key was pinned (the caller persists the state)
     */
    private boolean addSigningKeys(List<?> list) {
        Map<String, SigningKey> pinned = pinnedKeys();
        boolean changed = false;
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> k)) {
                noteError("signing_key_rejected");
                continue;
            }
            // Canonical codes (docs/spec/policy.md §3.1): malformed -> rejected; a kid pinned to
            // other bytes -> conflict; unknown/revoked endorser -> endorser_unknown; bad signature
            // -> endorsement_invalid.
            if (!(k.get("kid") instanceof String kid) || !kid.matches("[A-Za-z0-9._-]{1,64}")) {
                noteError("signing_key_rejected");
                continue;
            }
            // A revoked kid stays revoked; tt-core may still list it, so this is not an anomaly.
            if (revokedKids.contains(kid)) continue;
            if (!"Ed25519".equals(k.get("alg")) || !(k.get("public_key") instanceof String pk)
                || !(k.get("endorsed_by") instanceof String by) || !(k.get("endorsement") instanceof String end)) {
                noteError("signing_key_rejected");
                continue;
            }
            byte[] raw = Base64Url.decodeStrict(pk);
            byte[] sig = Base64Url.decodeStrict(end);
            if (raw == null || raw.length != 32 || sig == null || sig.length != 64) {
                noteError("signing_key_rejected");
                continue;
            }
            SigningKey have = pinned.get(kid);
            if (have != null) {
                if (!java.util.Arrays.equals(Base64Url.decodeStrict(have.publicKey()), raw)) noteError("signing_key_conflict");
                continue;
            }
            SigningKey endorserKey = revokedKids.contains(by) ? null : pinned.get(by);
            PublicKey endorser = endorserKey == null ? null : Ed25519.publicKey(endorserKey.publicKey());
            if (endorser == null) {
                noteError("signing_key_endorser_unknown");
                continue;
            }
            byte[] prefix = ("tt-fleet-key/v1\0" + kid + "\0").getBytes(StandardCharsets.ISO_8859_1);
            byte[] msg = new byte[prefix.length + raw.length];
            System.arraycopy(prefix, 0, msg, 0, prefix.length);
            System.arraycopy(raw, 0, msg, prefix.length, raw.length);
            if (!Ed25519.verify(endorser, msg, sig)) {
                noteError("signing_key_endorsement_invalid");
                continue;
            }
            SigningKey nk = new SigningKey(kid, pk);
            addedKeys.add(nk);
            pinned.put(kid, nk);
            changed = true;
        }
        return changed;
    }

    private void renew() {
        FleetClient f = fleet;
        Enrollment e = enrollment;
        if (f == null || e == null) return;
        try {
            Response r = f.renew();
            if (r.status() != 200 || !(r.json() instanceof Map<?, ?> m) || !(m.get("client_cert") instanceof String cert) || !(m.get("client_key") instanceof String key)) {
                noteError("renew_failed");
                return;
            }
            Enrollment ne = Enrollment.fromMap(e.toMap());
            ne.clientCert = cert;
            if (m.get("not_after") instanceof String na) ne.notAfter = na;
            persistIdentity(ne, key);
        } catch (IOException | GeneralSecurityException | RuntimeException ex) {
            noteError("renew_network");
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    private void revoke() {
        synchronized (lock) {
            revoked = true;
            persist();
            dropQueues();
        }
        noteError("source_revoked");
    }

    private void dropQueues() {
        killGen.incrementAndGet();
        List<Runnable> dropped = new ArrayList<>();
        sanitizeExec.getQueue().drainTo(dropped);
        for (Runnable r : dropped) {
            counters.eventsDroppedQueue.incrementAndGet();
            if (r instanceof Job j) pendingBytes.addAndGet(-j.raw.heldBytes);
        }
        Exporter e = exporter;
        if (e != null) e.clear();
    }

    /** Recomputes the state and the capture gate. Call with {@code lock} held. */
    private void recompute() {
        long now = System.currentTimeMillis();
        Policy p = policy;
        long maxAgeMs = (enrollment == null ? 86400 : enrollment.policyMaxAgeS) * 1000;
        String st;
        KeyRef key = null;
        if (kill || revoked) st = "killed";
        else if (p == null) st = rejected != null ? rejected : "no_policy";
        else if (!(now < p.notAfter) || (lastContactMs > 0 && now - lastContactMs > maxAgeMs)) st = "expired_policy";
        else if (ring == null) st = "key_missing";
        else {
            try {
                key = ring.select(p);
                st = heartbeatOk ? CAPTURING : "starting";
            } catch (Refused r) {
                st = "key_mismatch";
            }
        }
        // Capture only after a heartbeat in this process (kill switch and min_issued_seq known).
        if (st.equals(CAPTURING) && key != null && p != null && lastContactMs > 0) {
            Sanitizer cur = san;
            if (cur == null || cur.policy != p || !cur.key.kid().equals(key.kid()) || !java.util.Arrays.equals(cur.key.key(), key.key())
                || !java.util.Objects.equals(cur.rateOverrideBp(), overrideBp)) {
                san = new Sanitizer(p, key, overrideBp, null);
            }
        } else {
            if (st.equals(CAPTURING)) st = "starting";
            san = null;
        }
        if (!st.equals(state) && cfg.debug) System.err.println("[traffic-twin] state " + st);
        state = st;
    }

    /** Snapshot for tests and diagnostics. */
    public Map<String, Object> status() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("state", state);
        Exporter ex = exporter;
        m.put("queue", (long) (ex == null ? 0 : ex.size()));
        m.put("events_sent", counters.eventsSent.get());
        m.put("exchanges_seen", counters.exchangesSeen.get());
        m.put("sanitizer_errors", counters.sanitizerErrors.get());
        return m;
    }

    /** For tests: runs one heartbeat now. */
    public void heartbeatNow() {
        guarded(this::heartbeat);
    }

    /** For tests: polls the policy now. */
    public void pollPolicyNow() {
        guarded(this::pollPolicy);
    }
}
