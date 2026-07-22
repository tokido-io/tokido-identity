package io.tokido.identity.grant;

import org.apiguardian.api.API;

import java.time.Instant;
import java.util.Objects;

/**
 * The result of minting an access token: the serialized token value plus its
 * issuance and expiry instants (both derived from the engine's injected clock).
 *
 * @param value     the serialized token (a compact JWS); non-null
 * @param issuedAt  the {@code iat} instant; non-null
 * @param expiresAt the {@code exp} instant; non-null, strictly after {@code issuedAt}
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.2.0")
public record MintedToken(String value, Instant issuedAt, Instant expiresAt) {

    public MintedToken {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (!expiresAt.isAfter(issuedAt)) {
            throw new IllegalArgumentException("expiresAt must be after issuedAt");
        }
    }
}
