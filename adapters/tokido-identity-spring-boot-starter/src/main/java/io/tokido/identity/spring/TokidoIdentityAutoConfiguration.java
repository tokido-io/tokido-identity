package io.tokido.identity.spring;

import io.tokido.identity.config.DiscoveryConfig;
import io.tokido.identity.dev.InMemoryKeyStore;
import io.tokido.identity.engine.IdentityEngine;
import io.tokido.identity.http.Router;
import io.tokido.identity.key.KeyStore;
import io.tokido.identity.signing.TokenSigner;
import io.tokido.identity.engine.signing.NimbusTokenSigner;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.net.URI;
import java.time.Clock;

/** Wires discovery + JWKS from the Tokido engine. */
@AutoConfiguration
@EnableConfigurationProperties(TokidoIdentityProperties.class)
public class TokidoIdentityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public Clock tokidoClock() {
        return Clock.systemUTC();
    }

    @Bean
    @ConditionalOnMissingBean
    public KeyStore tokidoKeyStore(TokidoIdentityProperties props, Clock clock) {
        if (!props.isDevKeys()) {
            throw new IllegalStateException(
                    "No KeyStore bean is defined. Provide a production KeyStore bean, or set "
                    + "tokido.identity.dev-keys=true to use the EPHEMERAL dev key (never in production).");
        }
        return InMemoryKeyStore.ephemeral(clock);
    }

    @Bean
    @ConditionalOnMissingBean
    public TokenSigner tokidoTokenSigner() {
        return new NimbusTokenSigner();
    }

    @Bean
    @ConditionalOnMissingBean
    public IdentityEngine tokidoIdentityEngine(TokidoIdentityProperties props, KeyStore keyStore, Clock clock) {
        if (props.getIssuer() == null || props.getIssuer().isBlank()) {
            throw new IllegalStateException("tokido.identity.issuer is required");
        }
        return new IdentityEngine(new DiscoveryConfig(URI.create(props.getIssuer())), keyStore, clock);
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
