package io.tokido.identity.dev;

import io.tokido.identity.client.ClientStore;
import io.tokido.identity.client.RegisteredClient;
import io.tokido.identity.test.ClientStoreContract;
import io.tokido.identity.test.Fixtures;

/** {@link InMemoryClientStore} must satisfy the reusable {@link ClientStoreContract}. */
class InMemoryClientStoreContractTest extends ClientStoreContract {

    @Override
    protected ClientStore storeWith(RegisteredClient... clients) {
        InMemoryClientStore store = new InMemoryClientStore(Fixtures.stubSecretHasher());
        for (RegisteredClient c : clients) {
            store.registerHashed(c);
        }
        return store;
    }
}
