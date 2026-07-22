package io.tokido.identity.grant;

import io.tokido.identity.client.RegisteredClient;
import org.apiguardian.api.API;

import java.util.Objects;

/**
 * Everything a {@link GrantHandler} needs to service a token request: the parsed
 * {@link TokenRequest}, the already-authenticated {@link RegisteredClient}, and a
 * {@link TokenMinter} for producing signed tokens.
 *
 * <p>Constructed by the engine and only read by handlers, so future increments may
 * add components without breaking plugin handlers.
 *
 * @param request the parsed token request; non-null
 * @param client  the authenticated client; non-null
 * @param minter  the token minter; non-null
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.2.0")
public record GrantContext(TokenRequest request, RegisteredClient client, TokenMinter minter) {

    public GrantContext {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(client, "client");
        Objects.requireNonNull(minter, "minter");
    }
}
