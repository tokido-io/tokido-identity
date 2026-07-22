package io.tokido.identity.claims;

import org.apiguardian.api.API;

import java.util.Map;

/**
 * Plugin extension point for contributing additional claims to a token as it is
 * minted (locked decision D3). Invoked per token with a {@link ClaimsContext} so
 * enrichment can be targeted. Returned claims are merged into the token, but the
 * minter protects reserved protocol claims ({@code iss}, {@code sub}, {@code exp},
 * {@code iat}, {@code jti}, {@code aud}, {@code client_id}, {@code scope}) — an
 * enricher cannot override them.
 *
 * <p>Ordered, failure-isolated execution across many enrichers is an
 * {@code EventListener} concern arriving in a later increment; v0.2 runs enrichers
 * in registration order.
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.2.0")
public interface ClaimsEnricher {

    /**
     * Contribute additional claims for the token described by {@code context}.
     *
     * @param context the token being minted; non-null
     * @return a map of claim name to value to merge; non-null (may be empty)
     */
    Map<String, Object> enrich(ClaimsContext context);
}
