package io.github.ivseb.traffictwin;

import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/** Agent configuration. {@link #fromEnvironment()} reads the {@code TT_*} variables. */
public final class Config {
    /** URL of the Fleet/intake listener of tt-core (always https). */
    public String enrollUrl;
    /** Enrollment token {@code tte_<secret>.<ca pin>}. */
    public String enrollToken;
    /** Content of the HMAC key (TT_HMAC_KEY). */
    public String hmacKey;
    /** File holding the HMAC key (TT_HMAC_KEY_FILE). */
    public Path hmacKeyFile;
    /** Service name requested at enrollment (TT_SERVICE_NAME, else OTEL_SERVICE_NAME lowercased). */
    public String serviceName;
    /** Where the PKCS#12, the enrollment and the policy cache are kept (TT_STATE_DIR). */
    public Path stateDir;
    /** Informational instance name (TT_INSTANCE, default host name). */
    public String instance;
    public boolean debug;
    /** Overrides for tests and benchmarks (0 = use the values received from tt-core). */
    public long heartbeatIntervalMs;
    public long policyPollIntervalMs;
    public long exportFlushMs = 1000;
    /** Compress OTLP bodies with gzip (event.md 4.1 allows it). */
    public boolean gzip;

    private static final Pattern SVC = Pattern.compile("[a-z0-9][a-z0-9._-]{0,62}");

    /** Service name from the environment: TT_SERVICE_NAME, else OTEL_SERVICE_NAME, normalized; null if unusable. */
    public static String serviceNameFrom(Map<String, String> env) {
        String raw = env.get("TT_SERVICE_NAME");
        if (raw == null || raw.isEmpty()) raw = env.get("OTEL_SERVICE_NAME");
        if (raw == null || raw.isEmpty()) return null;
        String s = raw.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9._-]", "-").replaceFirst("^[^a-z0-9]+", "");
        if (s.length() > 63) s = s.substring(0, 63);
        return SVC.matcher(s).matches() ? s : null;
    }

    private static long ms(String v) {
        if (v == null || !v.matches("[0-9]{1,9}")) return 0;
        return Math.max(100, Long.parseLong(v));
    }

    public static Config fromEnvironment() {
        return fromEnvironment(System.getenv());
    }

    public static Config fromEnvironment(Map<String, String> env) {
        Config c = new Config();
        c.enrollUrl = env.get("TT_ENROLL_URL");
        c.enrollToken = env.get("TT_ENROLL_TOKEN");
        c.hmacKey = env.get("TT_HMAC_KEY");
        if (env.get("TT_HMAC_KEY_FILE") != null) c.hmacKeyFile = Path.of(env.get("TT_HMAC_KEY_FILE"));
        c.serviceName = serviceNameFrom(env);
        if (env.get("TT_STATE_DIR") != null) c.stateDir = Path.of(env.get("TT_STATE_DIR"));
        c.instance = env.get("TT_INSTANCE");
        c.debug = String.valueOf(env.get("TT_DEBUG")).matches("(?i)1|true|yes|debug");
        c.heartbeatIntervalMs = ms(env.get("TT_HEARTBEAT_INTERVAL_MS"));
        c.policyPollIntervalMs = ms(env.get("TT_POLICY_POLL_INTERVAL_MS"));
        long f = ms(env.get("TT_EXPORT_FLUSH_MS"));
        if (f > 0) c.exportFlushMs = f;
        c.gzip = String.valueOf(env.get("TT_EXPORT_GZIP")).matches("(?i)1|true|yes");
        return c;
    }

    /** True when TT_DISABLED is set to a truthy value. */
    public static boolean disabled(Map<String, String> env) {
        return String.valueOf(env.get("TT_DISABLED")).matches("(?i)1|true|yes");
    }
}
