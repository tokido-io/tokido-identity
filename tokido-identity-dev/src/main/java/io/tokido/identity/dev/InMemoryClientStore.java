package io.tokido.identity.dev;

import io.tokido.identity.client.ClientAuthenticationMethod;
import io.tokido.identity.client.ClientStore;
import io.tokido.identity.client.RegisteredClient;
import io.tokido.identity.client.SecretHasher;

import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * DEV-ONLY in-memory {@link ClientStore}. Client secrets are hashed on
 * registration via the injected {@link SecretHasher}; plaintext is never retained.
 * Not for production: the registry is ephemeral and process-local.
 */
public final class InMemoryClientStore implements ClientStore {

    private static final System.Logger LOG = System.getLogger(InMemoryClientStore.class.getName());

    private final SecretHasher hasher;
    private final ConcurrentHashMap<String, RegisteredClient> clients = new ConcurrentHashMap<>();

    public InMemoryClientStore(SecretHasher hasher) {
        this.hasher = Objects.requireNonNull(hasher, "hasher");
        LOG.log(System.Logger.Level.WARNING,
                "DEV in-memory ClientStore — not for production; registry is ephemeral and process-local");
    }

    /**
     * Register a confidential client, hashing its plaintext secret on store.
     *
     * @param clientId     unique client id
     * @param secret       the plaintext secret (hashed immediately, never retained)
     * @param grantTypes   allowed grant-type wire values
     * @param scopes       allowed scopes
     * @param authMethods  permitted token-endpoint auth methods
     */
    public void register(String clientId, String secret, Set<String> grantTypes,
                         Set<String> scopes, Set<ClientAuthenticationMethod> authMethods) {
        Objects.requireNonNull(secret, "secret");
        registerHashed(new RegisteredClient(clientId, hasher.hash(secret), grantTypes, scopes, authMethods));
    }

    /** Register a client whose secret is already hashed. */
    public void registerHashed(RegisteredClient client) {
        Objects.requireNonNull(client, "client");
        clients.put(client.clientId(), client);
    }

    @Override
    public Optional<RegisteredClient> findById(String clientId) {
        Objects.requireNonNull(clientId, "clientId");
        return Optional.ofNullable(clients.get(clientId));
    }
}
