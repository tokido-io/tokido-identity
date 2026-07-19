package io.tokido.identity.key;

import org.apiguardian.api.API;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Objects;

/**
 * An active or rotated signing key with its private and public material and
 * lifecycle timestamps. Held only inside the engine/keystore; never published.
 *
 * @param kid        JWS key id; non-null, non-blank
 * @param alg        signature algorithm; non-null
 * @param privateKey private key for signing; non-null
 * @param publicKey  matching public key; non-null
 * @param createdAt  creation instant; non-null
 * @param notAfter   end of validity (exclusive); null means no expiry; if set, must be after createdAt
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.1.0")
public record SigningKey(String kid, SignatureAlgorithm alg, PrivateKey privateKey,
                         PublicKey publicKey, Instant createdAt, Instant notAfter) {
    public SigningKey {
        Objects.requireNonNull(kid, "kid");
        if (kid.isBlank()) {
            throw new IllegalArgumentException("kid must not be blank");
        }
        Objects.requireNonNull(alg, "alg");
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(createdAt, "createdAt");
        if (notAfter != null && !notAfter.isAfter(createdAt)) {
            throw new IllegalArgumentException("notAfter must be after createdAt");
        }
    }

    /** A public-only view of this key for JWKS publication. */
    public VerificationKey toVerificationKey() {
        return new VerificationKey(kid, alg, publicKey, createdAt, notAfter);
    }
}
