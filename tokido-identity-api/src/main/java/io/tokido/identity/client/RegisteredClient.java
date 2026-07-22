package io.tokido.identity.client;

import org.apiguardian.api.API;

import java.util.Objects;
import java.util.Set;

/**
 * A confidential client registered with the authorization server. The secret is
 * held only in <strong>hashed</strong> form ({@code secretHash}); the plaintext
 * is never stored, logged, or returned. Grant types are wire strings (e.g.
 * {@code "client_credentials"}) so plugin-contributed grants are representable
 * without a closed enum.
 *
 * <p>v0.2 models confidential clients only: {@code secretHash} is required.
 *
 * @param clientId                  unique client identifier; non-null, non-blank
 * @param secretHash                opaque hashed secret (implementation-defined encoding); non-null, non-blank
 * @param allowedGrantTypes         grant-type wire values this client may use; non-null, immutable
 * @param allowedScopes             scopes this client may request; non-null, immutable
 * @param tokenEndpointAuthMethods  auth methods this client may use at the token endpoint; non-null, immutable
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.2.0")
public record RegisteredClient(
        String clientId,
        String secretHash,
        Set<String> allowedGrantTypes,
        Set<String> allowedScopes,
        Set<ClientAuthenticationMethod> tokenEndpointAuthMethods) {

    public RegisteredClient {
        Objects.requireNonNull(clientId, "clientId");
        if (clientId.isBlank()) {
            throw new IllegalArgumentException("clientId must not be blank");
        }
        Objects.requireNonNull(secretHash, "secretHash");
        if (secretHash.isBlank()) {
            throw new IllegalArgumentException("secretHash must not be blank");
        }
        allowedGrantTypes = Set.copyOf(Objects.requireNonNull(allowedGrantTypes, "allowedGrantTypes"));
        allowedScopes = Set.copyOf(Objects.requireNonNull(allowedScopes, "allowedScopes"));
        tokenEndpointAuthMethods =
                Set.copyOf(Objects.requireNonNull(tokenEndpointAuthMethods, "tokenEndpointAuthMethods"));
    }
}
