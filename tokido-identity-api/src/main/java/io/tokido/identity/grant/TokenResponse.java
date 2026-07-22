package io.tokido.identity.grant;

import org.apiguardian.api.API;

import java.time.Duration;
import java.util.Objects;
import java.util.Set;

/**
 * A successful token-endpoint response (RFC 6749 §5.1) returned by a
 * {@link GrantHandler}. The transport layer renders {@code expiresIn} as integer
 * seconds and {@code scope} as a space-delimited string.
 *
 * @param accessToken the issued access token (a signed JWS); non-null
 * @param tokenType   the token type, e.g. {@code "Bearer"}; non-null
 * @param expiresIn   lifetime of the access token; non-null
 * @param scope       the granted scopes (may be narrower than requested); non-null, immutable
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.2.0")
public record TokenResponse(String accessToken, String tokenType, Duration expiresIn, Set<String> scope) {

    public TokenResponse {
        Objects.requireNonNull(accessToken, "accessToken");
        Objects.requireNonNull(tokenType, "tokenType");
        Objects.requireNonNull(expiresIn, "expiresIn");
        scope = Set.copyOf(Objects.requireNonNull(scope, "scope"));
    }
}
