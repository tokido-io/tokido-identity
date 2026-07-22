package io.tokido.identity.grant;

import org.apiguardian.api.API;

import java.util.Locale;

/**
 * OAuth 2.0 token-endpoint error codes (RFC 6749 §5.2). {@link #code()} is the
 * wire value emitted in the {@code error} field of an error response.
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.2.0")
public enum OAuthError {

    /** The request is missing a parameter or is otherwise malformed. */
    INVALID_REQUEST,

    /** Client authentication failed (unknown client, bad secret, or disallowed method). */
    INVALID_CLIENT,

    /** The supplied grant (e.g. code, refresh token) is invalid. */
    INVALID_GRANT,

    /** The authenticated client is not permitted to use this grant type. */
    UNAUTHORIZED_CLIENT,

    /** The grant type is not supported by the authorization server. */
    UNSUPPORTED_GRANT_TYPE,

    /** The requested scope exceeds what the client is allowed. */
    INVALID_SCOPE,

    /** An unexpected server-side condition prevented fulfilling the request. */
    SERVER_ERROR;

    /** The RFC 6749 wire value, e.g. {@code "invalid_client"}. */
    public String code() {
        return name().toLowerCase(Locale.ROOT);
    }
}
