package io.tokido.identity.engine.grant;

import io.tokido.identity.client.RegisteredClient;
import io.tokido.identity.grant.AccessTokenRequest;
import io.tokido.identity.grant.GrantContext;
import io.tokido.identity.grant.GrantHandler;
import io.tokido.identity.grant.MintedToken;
import io.tokido.identity.grant.OAuthError;
import io.tokido.identity.grant.OAuthException;
import io.tokido.identity.grant.TokenRequest;
import io.tokido.identity.grant.TokenResponse;

import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Built-in {@code client_credentials} grant handler (RFC 6749 §4.4). The client is
 * already authenticated; this handler checks the grant is permitted for the client,
 * narrows requested scope to the client's allowed set, and mints an access token
 * whose subject is the client itself. Secure-by-default: scope is never widened.
 */
public final class ClientCredentialsGrantHandler implements GrantHandler {

    public static final String GRANT_TYPE = "client_credentials";
    private static final String TOKEN_TYPE = "Bearer";

    @Override
    public String grantType() {
        return GRANT_TYPE;
    }

    @Override
    public TokenResponse handle(GrantContext context) {
        RegisteredClient client = context.client();
        if (!client.allowedGrantTypes().contains(GRANT_TYPE)) {
            throw new OAuthException(OAuthError.UNAUTHORIZED_CLIENT,
                    "client is not permitted to use the client_credentials grant");
        }

        Set<String> granted = resolveScopes(context.request(), client);

        MintedToken minted = context.minter().mintAccessToken(new AccessTokenRequest(
                GRANT_TYPE, client, client.clientId(), granted, Set.of(), Map.of()));

        Duration expiresIn = Duration.between(minted.issuedAt(), minted.expiresAt());
        return new TokenResponse(minted.value(), TOKEN_TYPE, expiresIn, granted);
    }

    /**
     * Requested scopes must be a subset of the client's allowed scopes. An empty
     * request grants the client's full allowed set.
     */
    private static Set<String> resolveScopes(TokenRequest request, RegisteredClient client) {
        Set<String> requested = request.requestedScopes();
        if (requested.isEmpty()) {
            return client.allowedScopes();
        }
        Set<String> granted = new LinkedHashSet<>();
        for (String scope : requested) {
            if (!client.allowedScopes().contains(scope)) {
                throw new OAuthException(OAuthError.INVALID_SCOPE, "scope not allowed for this client: " + scope);
            }
            granted.add(scope);
        }
        return granted;
    }
}
