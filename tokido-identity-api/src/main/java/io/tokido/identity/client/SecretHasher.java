package io.tokido.identity.client;

import org.apiguardian.api.API;

/**
 * Strategy for hashing and verifying client secrets. The default implementation
 * ({@code Pbkdf2SecretHasher}) lives in the engine module; dev stores and the
 * framework adapter inject it, keeping this API module free of any hashing
 * algorithm and its dependencies.
 *
 * <p>Implementations must compare in <strong>constant time</strong> and must never
 * include the plaintext secret in log output or exception messages.
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.2.0")
public interface SecretHasher {

    /**
     * Hash a plaintext secret into an opaque, self-describing stored form.
     *
     * @param plaintextSecret the secret to hash; non-null
     * @return the stored hash representation
     */
    String hash(String plaintextSecret);

    /**
     * Verify a presented plaintext secret against a stored hash, in constant time.
     *
     * @param plaintextSecret the presented secret; non-null
     * @param storedHash      a value previously produced by {@link #hash(String)}
     * @return {@code true} iff the secret matches; {@code false} on mismatch or a malformed hash
     */
    boolean matches(String plaintextSecret, String storedHash);
}
