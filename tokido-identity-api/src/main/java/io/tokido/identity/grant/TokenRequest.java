package io.tokido.identity.grant;

import org.apiguardian.api.API;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * A parsed token-endpoint request handed to a {@link GrantHandler}. Carries the
 * grant type, the requested scopes, and the raw form parameters so grant-specific
 * inputs (added in later increments, e.g. {@code code}, {@code refresh_token}) are
 * reachable without changing this type. The authenticated client is supplied
 * separately via {@link GrantContext#client()}.
 *
 * @param grantType       the {@code grant_type} wire value; non-null, non-blank
 * @param requestedScopes scopes parsed from the {@code scope} parameter; non-null, immutable (empty if absent)
 * @param parameters      all raw form parameters; non-null, immutable
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.2.0")
public record TokenRequest(String grantType, Set<String> requestedScopes, Map<String, String> parameters) {

    public TokenRequest {
        Objects.requireNonNull(grantType, "grantType");
        if (grantType.isBlank()) {
            throw new IllegalArgumentException("grantType must not be blank");
        }
        requestedScopes = requestedScopes == null ? Set.of() : Set.copyOf(requestedScopes);
        parameters = parameters == null ? Map.of() : Map.copyOf(parameters);
    }
}
