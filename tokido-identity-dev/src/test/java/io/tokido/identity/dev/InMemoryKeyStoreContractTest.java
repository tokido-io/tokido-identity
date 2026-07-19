package io.tokido.identity.dev;

import io.tokido.identity.key.KeyStore;
import io.tokido.identity.test.Fixtures;
import io.tokido.identity.test.KeyStoreContract;

class InMemoryKeyStoreContractTest extends KeyStoreContract {
    @Override
    protected KeyStore createKeyStore() {
        return InMemoryKeyStore.ephemeral(Fixtures.fixedClock());
    }
}
