package io.tokido.identity.engine.grant;

import io.tokido.identity.grant.OAuthError;
import io.tokido.identity.grant.TokenResponse;

import java.util.Objects;

/**
 * The total outcome of a token-endpoint call: either a {@link Success} carrying the
 * {@link TokenResponse}, or an {@link Error} carrying the OAuth error. Kept
 * framework-free — the transport layer maps it to HTTP status codes and headers, so
 * no HTTP concepts leak into the engine.
 */
public sealed interface TokenResult permits TokenResult.Success, TokenResult.Error {

    /** A successful token issuance. */
    record Success(TokenResponse response) implements TokenResult {
        public Success {
            Objects.requireNonNull(response, "response");
        }
    }

    /**
     * A failed token request.
     *
     * @param error          the OAuth error code
     * @param description    a safe, human-readable description (never secret material)
     * @param basicChallenge whether the transport should answer 401 with {@code WWW-Authenticate: Basic}
     */
    record Error(OAuthError error, String description, boolean basicChallenge) implements TokenResult {
        public Error {
            Objects.requireNonNull(error, "error");
        }
    }
}
