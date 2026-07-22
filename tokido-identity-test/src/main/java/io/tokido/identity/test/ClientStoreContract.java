package io.tokido.identity.test;

import io.tokido.identity.client.ClientAuthenticationMethod;
import io.tokido.identity.client.ClientStore;
import io.tokido.identity.client.RegisteredClient;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Reusable contract any {@link ClientStore} must satisfy. Subclass and implement
 * {@link #storeWith(RegisteredClient...)} to seed a store with the given clients.
 */
public abstract class ClientStoreContract {

    protected abstract ClientStore storeWith(RegisteredClient... clients);

    private static RegisteredClient client(String id) {
        return new RegisteredClient(id, "hashed:" + id,
                Set.of("client_credentials"), Set.of("read"),
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
    }

    @Test
    protected void find_by_id_returns_registered_client() {
        RegisteredClient c1 = client("c1");
        ClientStore store = storeWith(c1);
        assertThat(store.findById("c1")).contains(c1);
    }

    @Test
    protected void find_by_id_returns_empty_for_unknown() {
        ClientStore store = storeWith(client("c1"));
        assertThat(store.findById("nope")).isEmpty();
    }

    @Test
    protected void distinct_clients_are_each_retrievable() {
        RegisteredClient c1 = client("c1");
        RegisteredClient c2 = client("c2");
        ClientStore store = storeWith(c1, c2);
        assertThat(store.findById("c1")).contains(c1);
        assertThat(store.findById("c2")).contains(c2);
    }
}
