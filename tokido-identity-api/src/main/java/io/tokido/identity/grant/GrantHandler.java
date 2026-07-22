package io.tokido.identity.grant;

import org.apiguardian.api.API;

/**
 * The plugin extension point for OAuth grant types (locked decision D3). Built-in
 * grants are themselves {@code GrantHandler}s, so consumers add their own grant
 * types by registering a bean — without modifying core. v0.2 ships the built-in
 * {@code client_credentials} handler in the engine.
 *
 * <p>A handler validates the request against the authenticated client, mints a
 * token via {@link GrantContext#minter()}, and returns a {@link TokenResponse}. It
 * signals protocol errors by throwing {@link OAuthException} with the appropriate
 * {@link OAuthError}.
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.2.0")
public interface GrantHandler {

    /**
     * The {@code grant_type} wire value this handler services (the registry key),
     * e.g. {@code "client_credentials"}.
     *
     * @return the grant-type wire value; non-null, non-blank
     */
    String grantType();

    /**
     * Handle a token request.
     *
     * @param context the request, authenticated client, and minter; non-null
     * @return the successful token response
     * @throws OAuthException on any typed OAuth protocol error
     */
    TokenResponse handle(GrantContext context);
}
