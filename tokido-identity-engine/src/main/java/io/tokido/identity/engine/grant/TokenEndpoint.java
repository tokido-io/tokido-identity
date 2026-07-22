package io.tokido.identity.engine.grant;

import io.tokido.identity.client.RegisteredClient;
import io.tokido.identity.engine.client.ClientAuthenticator;
import io.tokido.identity.grant.GrantContext;
import io.tokido.identity.grant.GrantHandler;
import io.tokido.identity.grant.OAuthError;
import io.tokido.identity.grant.OAuthException;
import io.tokido.identity.grant.TokenMinter;
import io.tokido.identity.grant.TokenRequest;
import io.tokido.identity.grant.TokenResponse;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Orchestrates a single token-endpoint request: authenticate the client, dispatch
 * by {@code grant_type}, run the handler, and produce a total {@link TokenResult}.
 * Any {@link OAuthException} becomes a typed {@code Error}; any other runtime
 * failure becomes {@code server_error} with no detail leaked.
 */
public final class TokenEndpoint {

    private final ClientAuthenticator authenticator;
    private final GrantRegistry registry;
    private final TokenMinter minter;

    public TokenEndpoint(ClientAuthenticator authenticator, GrantRegistry registry, TokenMinter minter) {
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
        this.registry = Objects.requireNonNull(registry, "registry");
        this.minter = Objects.requireNonNull(minter, "minter");
    }

    public TokenResult handle(String authorizationHeader, Map<String, String> formParams) {
        Map<String, String> form = formParams == null ? Map.of() : formParams;
        try {
            RegisteredClient client = authenticator.authenticate(authorizationHeader, form);
            String grantType = form.get("grant_type");
            if (grantType == null || grantType.isBlank()) {
                throw new OAuthException(OAuthError.INVALID_REQUEST, "missing grant_type");
            }
            GrantHandler handler = registry.get(grantType);
            TokenRequest request = new TokenRequest(grantType, parseScopes(form.get("scope")), form);
            TokenResponse response = handler.handle(new GrantContext(request, client, minter));
            return new TokenResult.Success(response);
        } catch (OAuthException e) {
            return new TokenResult.Error(e.error(), e.getMessage(), e.basicChallenge());
        } catch (RuntimeException e) {
            return new TokenResult.Error(OAuthError.SERVER_ERROR, "internal error", false);
        }
    }

    /** Parse a space-delimited {@code scope} value into an ordered set (RFC 6749 §3.3). */
    private static Set<String> parseScopes(String scope) {
        Set<String> scopes = new LinkedHashSet<>();
        if (scope != null) {
            for (String s : scope.trim().split("\\s+")) {
                if (!s.isEmpty()) {
                    scopes.add(s);
                }
            }
        }
        return scopes;
    }
}
