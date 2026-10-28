package io.github.ivseb.traffictwin.sanitizer;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;

/** Ed25519 verification with {@code java.security} (JDK 15+). */
public final class Ed25519 {
    private Ed25519() {}

    /** Public key from the raw 32 bytes (base64url, no padding); null if malformed. */
    public static PublicKey publicKey(String rawB64url) {
        byte[] raw = Base64Url.decodeStrict(rawB64url);
        if (raw == null || raw.length != 32) return null;
        return publicKey(raw);
    }

    public static PublicKey publicKey(byte[] raw) {
        if (raw.length != 32) return null;
        try {
            byte[] le = raw.clone();
            boolean xOdd = (le[31] & 0x80) != 0;
            le[31] &= 0x7f;
            byte[] be = new byte[le.length];
            for (int i = 0; i < le.length; i++) be[i] = le[le.length - 1 - i];
            EdECPoint point = new EdECPoint(xOdd, new BigInteger(1, be));
            return KeyFactory.getInstance("Ed25519").generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, point));
        } catch (GeneralSecurityException | RuntimeException e) {
            return null;
        }
    }

    public static boolean verify(PublicKey key, byte[] message, byte[] signature) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(key);
            s.update(message);
            return s.verify(signature);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }
}
