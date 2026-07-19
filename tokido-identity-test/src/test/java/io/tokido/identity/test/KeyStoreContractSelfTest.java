package io.tokido.identity.test;

import io.tokido.identity.key.KeyStore;

class KeyStoreContractSelfTest extends KeyStoreContract {
    @Override
    protected KeyStore createKeyStore() {
        return Fixtures.singleKeyStore(Fixtures.rsaSigningKey("kid"));
    }
}
