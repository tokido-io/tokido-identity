package io.tokido.identity.engine.grant;

import io.tokido.identity.claims.ClaimsContext;
import io.tokido.identity.claims.ClaimsEnricher;
import io.tokido.identity.config.DiscoveryConfig;
import io.tokido.identity.engine.Json;
import io.tokido.identity.grant.AccessTokenRequest;
import io.tokido.identity.grant.MintedToken;
import io.tokido.identity.grant.TokenMinter;
import io.tokido.identity.key.KeyStore;
import io.tokido.identity.signing.TokenSigner;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;

/**
 * Default {@link TokenMinter}: assembles the access-token claim set, runs the
 * registered {@link ClaimsEnricher}s, and signs the token via the injected
 * {@link TokenSigner}. All time comes from the injected {@link Clock}; the
 * {@code jti} from the injected supplier — so minting is deterministic under test.
 *
 * <p>Reserved protocol claims ({@code iss}, {@code sub}, {@code client_id},
 * {@code iat}, {@code exp}, {@code jti}, {@code scope}, {@code aud}) are written
 * <em>after</em> enrichers run, so an enricher can add claims but never override them.
 */
public final class AccessTokenMinter implements TokenMinter {

    /** Claims an enricher must not override; they are (re)written by the minter. */
    static final Set<String> RESERVED_CLAIMS =
            Set.of("iss", "sub", "client_id", "iat", "exp", "jti", "scope", "aud");

    private static final String TOKEN_TYPE = "access_token";

    private final TokenSigner signer;
    private final KeyStore keyStore;
    private final DiscoveryConfig config;
    private final Clock clock;
    private final Duration ttl;
    private final Set<String> defaultAudiences;
    private final Supplier<String> jtiSource;
    private final List<ClaimsEnricher> enrichers;

    public AccessTokenMinter(TokenSigner signer, KeyStore keyStore, DiscoveryConfig config, Clock clock,
                             Duration ttl, Set<String> defaultAudiences, Supplier<String> jtiSource,
                             List<ClaimsEnricher> enrichers) {
        this.signer = Objects.requireNonNull(signer, "signer");
        this.keyStore = Objects.requireNonNull(keyStore, "keyStore");
        this.config = Objects.requireNonNull(config, "config");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.ttl = Objects.requireNonNull(ttl, "ttl");
        if (ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must be positive");
        }
        this.defaultAudiences = Set.copyOf(Objects.requireNonNull(defaultAudiences, "defaultAudiences"));
        this.jtiSource = Objects.requireNonNull(jtiSource, "jtiSource");
        this.enrichers = List.copyOf(Objects.requireNonNull(enrichers, "enrichers"));
    }

    @Override
    public MintedToken mintAccessToken(AccessTokenRequest request) {
        Objects.requireNonNull(request, "request");
        Instant issuedAt = clock.instant().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        Instant expiresAt = issuedAt.plus(ttl);
        Set<String> scopes = new TreeSet<>(request.scopes()); // stable order in the claim
        Set<String> audiences = request.audiences().isEmpty() ? defaultAudiences : request.audiences();

        Map<String, Object> claims = new LinkedHashMap<>();
        // Enricher-contributed claims first; reserved protocol claims below overwrite them.
        for (ClaimsEnricher enricher : enrichers) {
            ClaimsContext ctx = new ClaimsContext(TOKEN_TYPE, request.grantType(),
                    request.client(), request.subject(), request.scopes());
            Map<String, Object> extra = enricher.enrich(ctx);
            if (extra != null) {
                extra.forEach((k, v) -> {
                    if (!RESERVED_CLAIMS.contains(k)) {
                        claims.put(k, v);
                    }
                });
            }
        }
        // Request-supplied additional claims (also subject to reserved-claim protection).
        request.additionalClaims().forEach((k, v) -> {
            if (!RESERVED_CLAIMS.contains(k)) {
                claims.put(k, v);
            }
        });

        claims.put("iss", config.issuer().toString());
        claims.put("sub", request.subject());
        claims.put("client_id", request.client().clientId());
        claims.put("iat", issuedAt.getEpochSecond());
        claims.put("exp", expiresAt.getEpochSecond());
        claims.put("jti", jtiSource.get());
        claims.put("scope", String.join(" ", scopes));
        claims.put("aud", new ArrayList<>(new TreeSet<>(audiences)));

        String jws = signer.sign(Json.write(claims), keyStore.currentSigningKey());
        return new MintedToken(jws, issuedAt, expiresAt);
    }
}
