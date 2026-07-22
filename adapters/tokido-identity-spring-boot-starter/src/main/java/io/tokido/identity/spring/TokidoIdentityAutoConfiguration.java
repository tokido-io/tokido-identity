package io.tokido.identity.spring;

import io.tokido.identity.claims.ClaimsEnricher;
import io.tokido.identity.client.ClientStore;
import io.tokido.identity.client.SecretHasher;
import io.tokido.identity.config.DiscoveryConfig;
import io.tokido.identity.dev.InMemoryClientStore;
import io.tokido.identity.dev.InMemoryKeyStore;
import io.tokido.identity.engine.IdentityEngine;
import io.tokido.identity.engine.client.Pbkdf2SecretHasher;
import io.tokido.identity.engine.signing.NimbusTokenSigner;
import io.tokido.identity.http.Router;
import io.tokido.identity.key.KeyStore;
import io.tokido.identity.signing.TokenSigner;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.net.URI;
import java.time.Clock;
import java.util.Set;

/** Wires discovery + JWKS and the client_credentials token endpoint from the Tokido engine. */
@AutoConfiguration
@EnableConfigurationProperties(TokidoIdentityProperties.class)
public class TokidoIdentityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public Clock tokidoClock() {
        return Clock.systemUTC();
    }

    /** Default signer; RS256 compact-JWS via Nimbus. Always on the classpath (engine dependency). */
    @Bean
    @ConditionalOnMissingBean
    public TokenSigner tokidoTokenSigner() {
        return new NimbusTokenSigner();
    }

    /** Default secret hasher; PBKDF2-HMAC-SHA256. Always on the classpath (engine dependency). */
    @Bean
    @ConditionalOnMissingBean
    public SecretHasher tokidoSecretHasher() {
        return new Pbkdf2SecretHasher();
    }

    /**
     * Dev-key fallback. tokido-identity-dev is an OPTIONAL dependency of the
     * starter, so this configuration only activates when the consumer has put
     * it on the classpath deliberately; production classpaths never carry the
     * ephemeral-key code path.
     *
     * <p>Deliberately NOT annotated {@code @Configuration}: it is processed as a
     * lite member of this auto-configuration only. A {@code @Configuration}
     * meta-{@code @Component} annotation would make it eligible for component
     * scanning, and an app scanning this package would then register it before
     * user beans, breaking {@code @ConditionalOnMissingBean} ordering.
     */
    @ConditionalOnClass(InMemoryKeyStore.class)
    static class DevKeyStoreConfiguration {

        @Bean
        @ConditionalOnMissingBean
        KeyStore tokidoKeyStore(TokidoIdentityProperties props, Clock clock) {
            if (!props.isDevKeys()) {
                throw new IllegalStateException(
                        "No KeyStore bean is defined. Provide a production KeyStore bean, or set "
                        + "tokido.identity.dev-keys=true to use the EPHEMERAL dev key (never in production).");
            }
            return InMemoryKeyStore.ephemeral(clock);
        }
    }

    /**
     * Dev client-registry fallback: an empty in-memory {@link ClientStore} so an app
     * that has the dev module on the classpath boots without registering clients.
     * Only activates when tokido-identity-dev is present and the consumer has not
     * supplied their own {@code ClientStore} (e.g. the example app registers a demo
     * client and that bean wins).
     */
    @ConditionalOnClass(InMemoryClientStore.class)
    static class DevClientStoreConfiguration {

        @Bean
        @ConditionalOnMissingBean
        ClientStore tokidoClientStore(SecretHasher secretHasher) {
            return new InMemoryClientStore(secretHasher);
        }
    }

    @Bean
    @ConditionalOnMissingBean
    public IdentityEngine tokidoIdentityEngine(TokidoIdentityProperties props,
                                               ObjectProvider<KeyStore> keyStore,
                                               ObjectProvider<ClientStore> clientStore,
                                               TokenSigner tokenSigner,
                                               SecretHasher secretHasher,
                                               ObjectProvider<ClaimsEnricher> claimsEnrichers,
                                               Clock clock) {
        if (props.getIssuer() == null || props.getIssuer().isBlank()) {
            throw new IllegalStateException("tokido.identity.issuer is required");
        }
        KeyStore ks = keyStore.getIfAvailable();
        if (ks == null) {
            throw new IllegalStateException(
                    "No KeyStore bean is defined and tokido-identity-dev is not on the classpath. "
                    + "Provide a production KeyStore bean, or add the optional io.tokido:tokido-identity-dev "
                    + "dependency and set tokido.identity.dev-keys=true (dev only, never in production).");
        }
        ClientStore cs = clientStore.getIfAvailable();
        if (cs == null) {
            throw new IllegalStateException(
                    "No ClientStore bean is defined and tokido-identity-dev is not on the classpath. "
                    + "Provide a production ClientStore bean, or add the optional io.tokido:tokido-identity-dev "
                    + "dependency (dev only) to get an in-memory registry.");
        }
        IdentityEngine.Builder builder = IdentityEngine.builder()
                .discoveryConfig(new DiscoveryConfig(URI.create(props.getIssuer())))
                .keyStore(ks)
                .clock(clock)
                .tokenSigner(tokenSigner)
                .clientStore(cs)
                .secretHasher(secretHasher)
                .accessTokenTtl(props.getAccessTokenTtl())
                .claimsEnrichers(claimsEnrichers.orderedStream().toList());
        if (props.getTokenAudience() != null && !props.getTokenAudience().isBlank()) {
            builder.tokenAudiences(Set.of(props.getTokenAudience()));
        }
        return builder.build();
    }

    @Bean
    @ConditionalOnMissingBean
    public Router tokidoRouter(IdentityEngine engine) {
        return new Router(engine);
    }

    @Bean
    @ConditionalOnMissingBean(DiscoveryController.class)
    public DiscoveryController tokidoDiscoveryController(Router router) {
        return new DiscoveryController(router);
    }
}
