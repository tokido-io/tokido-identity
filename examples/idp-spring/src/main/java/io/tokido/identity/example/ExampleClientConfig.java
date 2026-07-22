package io.tokido.identity.example;

import io.tokido.identity.client.ClientAuthenticationMethod;
import io.tokido.identity.client.ClientStore;
import io.tokido.identity.client.SecretHasher;
import io.tokido.identity.dev.InMemoryClientStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

/**
 * Registers a demo confidential client so the client_credentials flow can be
 * exercised with {@code curl}. DEV ONLY: the secret is a well-known literal and the
 * registry is in-memory.
 */
@Configuration
public class ExampleClientConfig {

    @Bean
    public ClientStore clientStore(SecretHasher hasher) {
        InMemoryClientStore store = new InMemoryClientStore(hasher);
        store.register(
                "demo-client",
                "demo-secret",
                Set.of("client_credentials"),
                Set.of("read", "write"),
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                        ClientAuthenticationMethod.CLIENT_SECRET_POST));
        return store;
    }
}
