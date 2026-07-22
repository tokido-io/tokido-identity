package io.tokido.identity.grant;

import org.apiguardian.api.API;

import java.util.Objects;

/**
 * A typed OAuth 2.0 protocol error raised during token-endpoint processing (client
 * authentication or grant handling). Carries the {@link OAuthError} and a safe,
 * human-readable description; it must <strong>never</strong> contain secret material.
 *
 * <p>{@link #basicChallenge()} signals that HTTP Basic authentication was attempted,
 * so the transport layer answers {@code invalid_client} with 401 and a
 * {@code WWW-Authenticate: Basic} challenge (RFC 6749 §5.2).
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.2.0")
public final class OAuthException extends RuntimeException {

    private final transient OAuthError error;
    private final boolean basicChallenge;

    public OAuthException(OAuthError error, String description) {
        this(error, description, false);
    }

    public OAuthException(OAuthError error, String description, boolean basicChallenge) {
        super(description);
        this.error = Objects.requireNonNull(error, "error");
        this.basicChallenge = basicChallenge;
    }

    /** The typed OAuth error code. */
    public OAuthError error() {
        return error;
    }

    /** Whether a {@code WWW-Authenticate: Basic} challenge should accompany the response. */
    public boolean basicChallenge() {
        return basicChallenge;
    }
}
