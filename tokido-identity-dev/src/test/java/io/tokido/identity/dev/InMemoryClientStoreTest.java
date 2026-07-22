package io.tokido.identity.dev;

import io.tokido.identity.client.ClientAuthenticationMethod;
import io.tokido.identity.client.RegisteredClient;
import io.tokido.identity.client.SecretHasher;
import io.tokido.identity.test.Fixtures;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryClientStoreTest {

    private final SecretHasher hasher = Fixtures.stubSecretHasher();

    @Test
    void register_hashes_secret_and_looks_up() {
        InMemoryClientStore store = new InMemoryClientStore(hasher);
        store.register("c1", "s3cret", Set.of("client_credentials"), Set.of("read"),
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));

        Optional<RegisteredClient> found = store.findById("c1");
        assertThat(found).isPresent();
        assertThat(found.get().secretHash()).isNotEqualTo("s3cret"); // stored hashed, not plaintext
        assertThat(hasher.matches("s3cret", found.get().secretHash())).isTrue();
    }

    @Test
    void unknown_client_is_empty() {
        assertThat(new InMemoryClientStore(hasher).findById("nope")).isEmpty();
    }

    @Test
    void register_hashed_stores_prebuilt_client() {
        InMemoryClientStore store = new InMemoryClientStore(hasher);
        RegisteredClient client = new RegisteredClient("c2", "hashed:x",
                Set.of("client_credentials"), Set.of("read"),
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_POST));
        store.registerHashed(client);
        assertThat(store.findById("c2")).contains(client);
    }
}
