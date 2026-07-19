package io.tokido.identity.key;

import org.apiguardian.api.API;

import java.security.PublicKey;
import java.time.Instant;
import java.util.Objects;

/**
 * Public verification key published in JWKS. Carries no private material.
 *
 * @param kid       JWS key id; non-null, non-blank
 * @param alg       signature algorithm; non-null
 * @param publicKey public key; non-null
 * @param createdAt creation instant; non-null
 * @param notAfter  end of validity (exclusive); null means no expiry; if set, must be after createdAt
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.1.0")
public record VerificationKey(String kid, SignatureAlgorithm alg, PublicKey publicKey,
                              Instant createdAt, Instant notAfter) {
    public VerificationKey {
        Objects.requireNonNull(kid, "kid");
        if (kid.isBlank()) {
            throw new IllegalArgumentException("kid must not be blank");
        }
        Objects.requireNonNull(alg, "alg");
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(createdAt, "createdAt");
        if (notAfter != null && !notAfter.isAfter(createdAt)) {
            throw new IllegalArgumentException("notAfter must be after createdAt");
        }
    }
}
