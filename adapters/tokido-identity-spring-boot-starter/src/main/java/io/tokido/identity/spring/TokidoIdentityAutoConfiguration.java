package io.tokido.identity.spring;

import io.tokido.identity.config.DiscoveryConfig;
import io.tokido.identity.dev.InMemoryKeyStore;
import io.tokido.identity.engine.IdentityEngine;
import io.tokido.identity.http.Router;
import io.tokido.identity.key.KeyStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
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

    // NOTE: a TokenSigner bean is added here in v0.2 when IdentityEngine mints tokens.

    @Bean
    @ConditionalOnMissingBean
    public IdentityEngine tokidoIdentityEngine(TokidoIdentityProperties props,
                                               ObjectProvider<KeyStore> keyStore, Clock clock) {
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
        return new IdentityEngine(new DiscoveryConfig(URI.create(props.getIssuer())), ks, clock);
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
