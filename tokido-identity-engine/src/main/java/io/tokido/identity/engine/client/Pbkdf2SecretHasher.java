package io.tokido.identity.engine.client;

import io.tokido.identity.client.SecretHasher;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Default {@link SecretHasher}: PBKDF2-HMAC-SHA256 with a random per-secret salt.
 * JDK-only (no external dependency). Hashes are self-describing so the algorithm
 * and cost can evolve without a storage migration:
 *
 * <pre>pbkdf2-sha256$&lt;iterations&gt;$&lt;base64 salt&gt;$&lt;base64 derived-key&gt;</pre>
 *
 * <p>{@link #matches} recomputes with the stored parameters and compares in
 * constant time. A plaintext secret never appears in any exception or log.
 */
public final class Pbkdf2SecretHasher implements SecretHasher {

    private static final String PREFIX = "pbkdf2-sha256";
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int DEFAULT_ITERATIONS = 210_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;

    private final SecureRandom random = new SecureRandom();
    private final int iterations;

    public Pbkdf2SecretHasher() {
        this(DEFAULT_ITERATIONS);
    }

    public Pbkdf2SecretHasher(int iterations) {
        if (iterations < 1) {
            throw new IllegalArgumentException("iterations must be positive");
        }
        this.iterations = iterations;
    }

    @Override
    public String hash(String plaintextSecret) {
        Objects.requireNonNull(plaintextSecret, "plaintextSecret");
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] derived = pbkdf2(plaintextSecret, salt, iterations);
        Base64.Encoder enc = Base64.getEncoder().withoutPadding();
        return PREFIX + "$" + iterations + "$" + enc.encodeToString(salt) + "$" + enc.encodeToString(derived);
    }

    @Override
    public boolean matches(String plaintextSecret, String storedHash) {
        Objects.requireNonNull(plaintextSecret, "plaintextSecret");
        if (storedHash == null) {
            return false;
        }
        String[] parts = storedHash.split("\\$");
        if (parts.length != 4 || !PREFIX.equals(parts[0])) {
            return false;
        }
        try {
            int iters = Integer.parseInt(parts[1]);
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            byte[] actual = pbkdf2(plaintextSecret, salt, iters);
            return MessageDigest.isEqual(expected, actual);
        } catch (RuntimeException e) {
            // Malformed stored hash (bad number/base64) → treat as non-match, never leak input.
            return false;
        }
    }

    private static byte[] pbkdf2(String secret, byte[] salt, int iterations) {
        char[] chars = secret.toCharArray();
        KeySpec spec = new PBEKeySpec(chars, salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("PBKDF2 derivation failed", e);
        } finally {
            spec = null;
            java.util.Arrays.fill(chars, '\0');
        }
    }
}
