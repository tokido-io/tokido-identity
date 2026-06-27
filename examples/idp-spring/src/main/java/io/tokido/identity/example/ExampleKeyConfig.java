package io.tokido.identity.example;

import io.tokido.identity.dev.InMemoryKeyStore;
import io.tokido.identity.key.KeyStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.nio.charset.StandardCharsets;
import java.time.Clock;

/** Pins a stable dev key so the example's kid/JWKS are stable across restarts. */
@Configuration
public class ExampleKeyConfig {

    @Bean
    public KeyStore keyStore(Clock clock) throws Exception {
        String priv = new String(new ClassPathResource("dev-private-key.pem")
                .getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        String pub = new String(new ClassPathResource("dev-public-key.pem")
                .getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        return InMemoryKeyStore.fromPem(priv, pub, "example-dev-key", clock);
    }
}
