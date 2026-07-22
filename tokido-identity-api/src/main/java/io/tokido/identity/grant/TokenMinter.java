package io.tokido.identity.grant;

import org.apiguardian.api.API;

/**
 * Capability handed to a {@link GrantHandler} for minting signed access tokens
 * without knowing about signing keys or JOSE. The default implementation lives in
 * the engine and assembles the protocol claims, runs the registered
 * {@link io.tokido.identity.claims.ClaimsEnricher}s, and signs the token.
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.2.0")
public interface TokenMinter {

    /**
     * Mint a signed access token for the given request.
     *
     * @param request the grant-decided token parameters; non-null
     * @return the minted token with its issuance/expiry instants
     */
    MintedToken mintAccessToken(AccessTokenRequest request);
}
