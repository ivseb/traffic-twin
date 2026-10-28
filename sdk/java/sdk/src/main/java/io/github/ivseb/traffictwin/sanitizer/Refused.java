package io.github.ivseb.traffictwin.sanitizer;

/**
 * The source must not capture (sanitizer.md 1, policy.md 4). The code is one of the heartbeat
 * states: {@code no_policy}, {@code policy_rejected}, {@code expired_policy}, {@code key_missing},
 * {@code key_mismatch}. The detail never contains payload values.
 */
public final class Refused extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /** Detail prefix of a refusal raised by the v1.3 safety subset (hardening.md 2); reported as {@code policy_unsafe}. */
    public static final String UNSAFE = "unsafe";

    private final String code;
    private final String detail;

    public Refused(String code) {
        this(code, "");
    }

    public Refused(String code, String detail) {
        super(detail.isEmpty() ? code : code + ": " + detail, null, false, false);
        this.code = code;
        this.detail = detail;
    }

    public String detail() {
        return detail;
    }

    /** True when the policy was refused by the safety subset H1 to H3 (hardening.md 2.1). */
    public boolean isUnsafe() {
        return detail.startsWith(UNSAFE);
    }

    public String code() {
        return code;
    }
}
