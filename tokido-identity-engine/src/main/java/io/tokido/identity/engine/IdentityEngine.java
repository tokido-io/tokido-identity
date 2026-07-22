package io.tokido.identity.engine;

import io.tokido.identity.claims.ClaimsEnricher;
import io.tokido.identity.client.ClientAuthenticationMethod;
import io.tokido.identity.client.ClientStore;
import io.tokido.identity.client.SecretHasher;
import io.tokido.identity.config.DiscoveryConfig;
import io.tokido.identity.engine.client.ClientAuthenticator;
import io.tokido.identity.engine.grant.AccessTokenMinter;
import io.tokido.identity.engine.grant.ClientCredentialsGrantHandler;
import io.tokido.identity.engine.grant.GrantRegistry;
import io.tokido.identity.engine.grant.TokenEndpoint;
import io.tokido.identity.engine.grant.TokenResult;
import io.tokido.identity.grant.GrantHandler;
import io.tokido.identity.grant.TokenMinter;
import io.tokido.identity.key.KeyStore;
import io.tokido.identity.protocol.DiscoveryDocument;
import io.tokido.identity.protocol.JsonWebKeySet;
import io.tokido.identity.signing.TokenSigner;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * The framework-free, deterministic protocol engine. Serves discovery and JWKS and,
 * when wired via {@link #builder()}, mints {@code client_credentials} access tokens
 * at the token endpoint. The injected {@link Clock} is the single time source (no
 * wall-clock calls anywhere in the engine).
 *
 * <p>The legacy three-argument constructor wires a discovery/JWKS-only engine; its
 * {@link #token} method is unavailable and discovery advertises no grant types or
 * token-endpoint auth methods (feature-derived: nothing is wired).
 */
public final class IdentityEngine {

    private final DiscoveryConfig config;
    private final KeyStore keyStore;
    private final Clock clock;
    private final TokenEndpoint tokenEndpoint; // null when discovery/JWKS-only
    private final List<String> grantTypesSupported;
    private final List<String> tokenEndpointAuthMethodsSupported;

    /** Discovery/JWKS-only engine (no token endpoint). */
    public IdentityEngine(DiscoveryConfig config, KeyStore keyStore, Clock clock) {
        this(config, keyStore, clock, null, List.of(), List.of());
    }

    private IdentityEngine(DiscoveryConfig config, KeyStore keyStore, Clock clock,
                           TokenEndpoint tokenEndpoint, List<String> grantTypesSupported,
                           List<String> tokenEndpointAuthMethodsSupported) {
        this.config = Objects.requireNonNull(config, "config");
        this.keyStore = Objects.requireNonNull(keyStore, "keyStore");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.tokenEndpoint = tokenEndpoint;
        this.grantTypesSupported = List.copyOf(grantTypesSupported);
        this.tokenEndpointAuthMethodsSupported = List.copyOf(tokenEndpointAuthMethodsSupported);
    }

    public static Builder builder() {
        return new Builder();
    }

    public DiscoveryDocument discovery() {
        return Discovery.build(config, keyStore, grantTypesSupported, tokenEndpointAuthMethodsSupported);
    }

    public JsonWebKeySet jwks() {
        return Jwks.from(keyStore);
    }

    public String discoveryJson() {
        return Json.write(discovery().toOrderedMap());
    }

    public String jwksJson() {
        return Json.write(jwks());
    }

    /**
     * Handle a token-endpoint request.
     *
     * @param authorizationHeader the raw {@code Authorization} header value, or null
     * @param formParams          the parsed {@code application/x-www-form-urlencoded} body
     * @return the total token result (success or typed error)
     * @throws IllegalStateException if this engine was not built with a token endpoint
     */
    public TokenResult token(String authorizationHeader, Map<String, String> formParams) {
        if (tokenEndpoint == null) {
            throw new IllegalStateException("token endpoint not configured; build via IdentityEngine.builder()");
        }
        return tokenEndpoint.handle(authorizationHeader, formParams);
    }

    public Clock clock() {
        return clock;
    }

    // package-private: for cross-instance signing tests only; not public API.
    io.tokido.identity.key.SigningKey currentForTest() {
        return keyStore.currentSigningKey();
    }

    /** Builder for a token-issuing engine. Collaborators grow per increment. */
    public static final class Builder {

        private DiscoveryConfig config;
        private KeyStore keyStore;
        private Clock clock = Clock.systemUTC();
        private TokenSigner tokenSigner;
        private ClientStore clientStore;
        private SecretHasher secretHasher;
        private List<GrantHandler> grantHandlers;
        private List<ClaimsEnricher> claimsEnrichers = List.of();
        private Duration accessTokenTtl = Duration.ofHours(1);
        private Set<String> tokenAudiences;
        private Supplier<String> jtiSource = () -> UUID.randomUUID().toString();
        private Set<ClientAuthenticationMethod> tokenEndpointAuthMethods =
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                        ClientAuthenticationMethod.CLIENT_SECRET_POST);

        private Builder() {
        }

        public Builder discoveryConfig(DiscoveryConfig config) {
            this.config = config;
            return this;
        }

        public Builder keyStore(KeyStore keyStore) {
            this.keyStore = keyStore;
            return this;
        }

        public Builder clock(Clock clock) {
            this.clock = clock;
            return this;
        }

        public Builder tokenSigner(TokenSigner tokenSigner) {
            this.tokenSigner = tokenSigner;
            return this;
        }

        public Builder clientStore(ClientStore clientStore) {
            this.clientStore = clientStore;
            return this;
        }

        public Builder secretHasher(SecretHasher secretHasher) {
            this.secretHasher = secretHasher;
            return this;
        }

        public Builder grantHandlers(List<GrantHandler> grantHandlers) {
            this.grantHandlers = grantHandlers;
            return this;
        }

        public Builder claimsEnrichers(List<ClaimsEnricher> claimsEnrichers) {
            this.claimsEnrichers = claimsEnrichers == null ? List.of() : List.copyOf(claimsEnrichers);
            return this;
        }

        public Builder accessTokenTtl(Duration accessTokenTtl) {
            this.accessTokenTtl = accessTokenTtl;
            return this;
        }

        public Builder tokenAudiences(Set<String> tokenAudiences) {
            this.tokenAudiences = tokenAudiences;
            return this;
        }

        public Builder jtiSource(Supplier<String> jtiSource) {
            this.jtiSource = jtiSource;
            return this;
        }

        public Builder tokenEndpointAuthMethods(Set<ClientAuthenticationMethod> methods) {
            this.tokenEndpointAuthMethods = Set.copyOf(methods);
            return this;
        }

        public IdentityEngine build() {
            Objects.requireNonNull(config, "config");
            Objects.requireNonNull(keyStore, "keyStore");
            Objects.requireNonNull(tokenSigner, "tokenSigner");
            Objects.requireNonNull(clientStore, "clientStore");
            Objects.requireNonNull(secretHasher, "secretHasher");

            List<GrantHandler> handlers = grantHandlers == null
                    ? List.of(new ClientCredentialsGrantHandler())
                    : List.copyOf(grantHandlers);
            Set<String> audiences = tokenAudiences == null
                    ? Set.of(config.issuer().toString())
                    : Set.copyOf(tokenAudiences);

            TokenMinter minter = new AccessTokenMinter(tokenSigner, keyStore, config, clock,
                    accessTokenTtl, audiences, jtiSource, claimsEnrichers);
            ClientAuthenticator authenticator = new ClientAuthenticator(clientStore, secretHasher);
            GrantRegistry registry = new GrantRegistry(handlers);
            TokenEndpoint endpoint = new TokenEndpoint(authenticator, registry, minter);

            List<String> grantTypes = List.copyOf(registry.grantTypes());
            List<String> authMethods = tokenEndpointAuthMethods.stream()
                    .map(ClientAuthenticationMethod::wireValue).sorted().toList();

            return new IdentityEngine(config, keyStore, clock, endpoint, grantTypes, authMethods);
        }
    }
}
