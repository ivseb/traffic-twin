package io.github.ivseb.traffictwin.sanitizer;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/** Local HMAC keys (sanitizer.md 7.1): one or more {@code kid:base64url} lines. */
public final class KeyRing {
    private static final Pattern KID = Pattern.compile("[a-z0-9]{1,8}");

    /** A selected key. */
    public record KeyRef(String kid, byte[] key) {}

    private final Map<String, byte[]> keys;
    private final List<String> order;

    private KeyRing(Map<String, byte[]> keys, List<String> order) {
        this.keys = keys;
        this.order = order;
    }

    /** Parses the content of TT_HMAC_KEY / TT_HMAC_KEY_FILE. Throws {@code Refused(key_missing)}. */
    public static KeyRing parse(String text) {
        if (text == null) throw new Refused("key_missing", "absent");
        Map<String, byte[]> keys = new LinkedHashMap<>();
        List<String> order = new ArrayList<>();
        for (String line0 : text.split("\n", -1)) {
            String line = line0.endsWith("\r") ? line0.substring(0, line0.length() - 1) : line0;
            if (line.isEmpty()) continue;
            int c = line.indexOf(':');
            if (c < 0) throw new Refused("key_missing", "malformed");
            String kid = line.substring(0, c);
            if (!KID.matcher(kid).matches()) throw new Refused("key_missing", "kid");
            byte[] raw = Base64Url.decodeStrict(line.substring(c + 1));
            if (raw == null || raw.length < 32) throw new Refused("key_missing", "key bytes");
            if (!keys.containsKey(kid)) {
                keys.put(kid, raw);
                order.add(kid);
            }
        }
        if (keys.isEmpty()) throw new Refused("key_missing", "empty");
        return new KeyRing(keys, order);
    }

    public List<String> kids() {
        return order;
    }

    /** 7.1: picks the key for a policy (hmac.kid, then accept_kids in order). */
    public KeyRef select(Policy policy) {
        byte[] k = keys.get(policy.kid);
        if (k != null) return new KeyRef(policy.kid, k);
        for (String kid : policy.acceptKids) {
            byte[] a = keys.get(kid);
            if (a != null) return new KeyRef(kid, a);
        }
        throw new Refused("key_mismatch");
    }
}
