package io.tokido.identity.client;

import org.apiguardian.api.API;

import java.util.Optional;

/**
 * Storage SPI for the client registry. Synchronous and blocking (ADR-0002); the
 * engine calls it while handling a token request. Implementations must be safe
 * for concurrent reads.
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.2.0")
public interface ClientStore {

    /**
     * Look up a registered client by its {@code client_id}.
     *
     * @param clientId the client identifier; non-null
     * @return the client, or {@link Optional#empty()} if unknown
     */
    Optional<RegisteredClient> findById(String clientId);
}
