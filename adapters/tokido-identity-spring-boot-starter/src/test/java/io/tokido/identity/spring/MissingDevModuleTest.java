package io.tokido.identity.spring;

import io.tokido.identity.dev.InMemoryClientStore;
import io.tokido.identity.dev.InMemoryKeyStore;
import io.tokido.identity.key.KeyStore;
import io.tokido.identity.test.Fixtures;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * tokido-identity-dev is an optional dependency of the starter: production
 * classpaths without it must fail fast with an actionable message, never a
 * NoClassDefFoundError.
 */
class MissingDevModuleTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(TokidoIdentityAutoConfiguration.class))
            .withPropertyValues("tokido.identity.issuer=https://idp.example.com");

    @Test
    void fails_with_clear_message_when_dev_module_absent_and_no_keystore_bean() {
        runner.withClassLoader(new FilteredClassLoader(InMemoryKeyStore.class))
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(ctx.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("KeyStore");
                });
    }

    @Test
    void dev_keys_property_without_dev_module_names_the_missing_dependency() {
        runner.withClassLoader(new FilteredClassLoader(InMemoryKeyStore.class))
                .withPropertyValues("tokido.identity.dev-keys=true")
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(ctx.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("tokido-identity-dev");
                });
    }

    @Test
    void fails_with_clear_message_when_client_store_missing() {
        // A KeyStore bean is present, but the dev ClientStore fallback is filtered out
        // and no user ClientStore bean is defined → fail fast naming ClientStore.
        runner.withClassLoader(new FilteredClassLoader(InMemoryClientStore.class))
                .withBean(KeyStore.class, () -> Fixtures.singleKeyStore(Fixtures.rsaSigningKey("k")))
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(ctx.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("ClientStore");
                });
    }
}
