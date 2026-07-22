package io.tokido.identity.engine.client;

import io.tokido.identity.client.ClientAuthenticationMethod;
import io.tokido.identity.client.ClientStore;
import io.tokido.identity.client.RegisteredClient;
import io.tokido.identity.client.SecretHasher;
import io.tokido.identity.grant.OAuthError;
import io.tokido.identity.grant.OAuthException;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Authenticates the client presenting a token request via {@code client_secret_basic}
 * (HTTP Basic header) or {@code client_secret_post} (form parameters). Secret
 * comparison is constant-time (delegated to {@link SecretHasher}); no secret
 * material ever appears in an exception message.
 *
 * <p>Failure modes (RFC 6749 §5.2): presenting both methods at once →
 * {@code invalid_request}; unknown client / bad secret / disallowed method →
 * {@code invalid_client} (with a Basic challenge flag when the Basic header was used).
 */
public final class ClientAuthenticator {

    private final ClientStore store;
    private final SecretHasher hasher;

    public ClientAuthenticator(ClientStore store, SecretHasher hasher) {
        this.store = Objects.requireNonNull(store, "store");
        this.hasher = Objects.requireNonNull(hasher, "hasher");
    }

    /**
     * @param authorizationHeader the raw {@code Authorization} header value, or null
     * @param formParams          the parsed form parameters
     * @return the authenticated client
     * @throws OAuthException {@code invalid_request} or {@code invalid_client} on failure
     */
    public RegisteredClient authenticate(String authorizationHeader, Map<String, String> formParams) {
        Map<String, String> form = formParams == null ? Map.of() : formParams;
        boolean basicPresent = authorizationHeader != null
                && authorizationHeader.regionMatches(true, 0, "Basic ", 0, 6);
        boolean postPresent = form.containsKey("client_id");

        if (basicPresent && postPresent) {
            throw new OAuthException(OAuthError.INVALID_REQUEST,
                    "multiple client authentication methods in one request");
        }
        if (basicPresent) {
            return viaBasic(authorizationHeader, form);
        }
        if (postPresent) {
            return viaPost(form);
        }
        throw new OAuthException(OAuthError.INVALID_CLIENT, "no client credentials presented");
    }

    private RegisteredClient viaBasic(String header, Map<String, String> form) {
        Credentials creds = decodeBasic(header)
                .orElseThrow(() -> new OAuthException(OAuthError.INVALID_CLIENT,
                        "malformed Basic authorization header", true));
        return verify(creds.clientId(), creds.secret(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC, true);
    }

    private RegisteredClient viaPost(Map<String, String> form) {
        String clientId = form.get("client_id");
        String secret = form.get("client_secret");
        return verify(clientId, secret, ClientAuthenticationMethod.CLIENT_SECRET_POST, false);
    }

    private RegisteredClient verify(String clientId, String secret,
                                    ClientAuthenticationMethod method, boolean basicChallenge) {
        if (clientId == null || clientId.isBlank() || secret == null) {
            throw new OAuthException(OAuthError.INVALID_CLIENT, "invalid client credentials", basicChallenge);
        }
        RegisteredClient client = store.findById(clientId)
                .orElseThrow(() -> new OAuthException(OAuthError.INVALID_CLIENT,
                        "invalid client credentials", basicChallenge));
        if (!hasher.matches(secret, client.secretHash())) {
            throw new OAuthException(OAuthError.INVALID_CLIENT, "invalid client credentials", basicChallenge);
        }
        if (!client.tokenEndpointAuthMethods().contains(method)) {
            throw new OAuthException(OAuthError.INVALID_CLIENT,
                    "authentication method not permitted for this client", basicChallenge);
        }
        return client;
    }

    private static Optional<Credentials> decodeBasic(String header) {
        try {
            String b64 = header.substring("Basic ".length()).trim();
            String decoded = new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon < 0) {
                return Optional.empty();
            }
            String id = URLDecoder.decode(decoded.substring(0, colon), StandardCharsets.UTF_8);
            String secret = URLDecoder.decode(decoded.substring(colon + 1), StandardCharsets.UTF_8);
            return Optional.of(new Credentials(id, secret));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    private record Credentials(String clientId, String secret) {
    }
}
