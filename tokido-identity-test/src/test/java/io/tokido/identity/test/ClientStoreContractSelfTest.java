package io.tokido.identity.test;

import io.tokido.identity.client.ClientStore;
import io.tokido.identity.client.RegisteredClient;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/** Self-test: a trivial map-backed store must satisfy the {@link ClientStoreContract}. */
class ClientStoreContractSelfTest extends ClientStoreContract {

    @Override
    protected ClientStore storeWith(RegisteredClient... clients) {
        Map<String, RegisteredClient> map = new LinkedHashMap<>();
        for (RegisteredClient c : clients) {
            map.put(c.clientId(), c);
        }
        return clientId -> Optional.ofNullable(map.get(clientId));
    }
}
