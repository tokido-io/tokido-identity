package io.tokido.identity.spring;

import io.tokido.identity.dev.InMemoryKeyStore;
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
}
