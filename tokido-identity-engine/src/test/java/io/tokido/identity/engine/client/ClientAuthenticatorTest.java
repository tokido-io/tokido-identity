package io.tokido.identity.engine.client;

import io.tokido.identity.client.ClientAuthenticationMethod;
import io.tokido.identity.client.ClientStore;
import io.tokido.identity.client.RegisteredClient;
import io.tokido.identity.grant.OAuthError;
import io.tokido.identity.grant.OAuthException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientAuthenticatorTest {

    private final Pbkdf2SecretHasher hasher = new Pbkdf2SecretHasher(10_000);

    private ClientAuthenticator authenticatorFor(RegisteredClient client) {
        ClientStore store = clientId -> client.clientId().equals(clientId) ? Optional.of(client) : Optional.empty();
        return new ClientAuthenticator(store, hasher);
    }

    private RegisteredClient client(String secret, Set<ClientAuthenticationMethod> methods) {
        return new RegisteredClient("c1", hasher.hash(secret),
                Set.of("client_credentials"), Set.of("read"), methods);
    }

    private static String basic(String id, String secret) {
        String raw = id + ":" + secret;
        return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void authenticates_via_basic() {
        var auth = authenticatorFor(client("s3cret", Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)));
        RegisteredClient c = auth.authenticate(basic("c1", "s3cret"), Map.of());
        assertThat(c.clientId()).isEqualTo("c1");
    }

    @Test
    void authenticates_via_post() {
        var auth = authenticatorFor(client("s3cret", Set.of(ClientAuthenticationMethod.CLIENT_SECRET_POST)));
        RegisteredClient c = auth.authenticate(null, Map.of("client_id", "c1", "client_secret", "s3cret"));
        assertThat(c.clientId()).isEqualTo("c1");
    }

    @Test
    void basic_secret_is_form_url_decoded() {
        // Stored secret is "a b"; presented as the form-encoded "a%20b" inside Basic.
        var auth = authenticatorFor(client("a b", Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)));
        RegisteredClient c = auth.authenticate(basic("c1", "a%20b"), Map.of());
        assertThat(c.clientId()).isEqualTo("c1");
    }

    @Test
    void rejects_both_methods_at_once() {
        var auth = authenticatorFor(client("s3cret",
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST)));
        assertThatThrownBy(() -> auth.authenticate(basic("c1", "s3cret"), Map.of("client_id", "c1")))
                .isInstanceOfSatisfying(OAuthException.class,
                        e -> assertThat(e.error()).isEqualTo(OAuthError.INVALID_REQUEST));
    }

    @Test
    void unknown_client_is_invalid_client_with_basic_challenge_when_basic_used() {
        var auth = authenticatorFor(client("s3cret", Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)));
        assertThatThrownBy(() -> auth.authenticate(basic("nope", "s3cret"), Map.of()))
                .isInstanceOfSatisfying(OAuthException.class, e -> {
                    assertThat(e.error()).isEqualTo(OAuthError.INVALID_CLIENT);
                    assertThat(e.basicChallenge()).isTrue();
                });
    }

    @Test
    void wrong_secret_is_invalid_client() {
        var auth = authenticatorFor(client("s3cret", Set.of(ClientAuthenticationMethod.CLIENT_SECRET_POST)));
        assertThatThrownBy(() -> auth.authenticate(null, Map.of("client_id", "c1", "client_secret", "WRONG")))
                .isInstanceOfSatisfying(OAuthException.class, e -> {
                    assertThat(e.error()).isEqualTo(OAuthError.INVALID_CLIENT);
                    assertThat(e.basicChallenge()).isFalse();
                });
    }

    @Test
    void disallowed_method_is_invalid_client() {
        // Client only permits POST, but Basic is attempted.
        var auth = authenticatorFor(client("s3cret", Set.of(ClientAuthenticationMethod.CLIENT_SECRET_POST)));
        assertThatThrownBy(() -> auth.authenticate(basic("c1", "s3cret"), Map.of()))
                .isInstanceOfSatisfying(OAuthException.class, e -> {
                    assertThat(e.error()).isEqualTo(OAuthError.INVALID_CLIENT);
                    assertThat(e.basicChallenge()).isTrue();
                });
    }

    @Test
    void missing_credentials_is_invalid_client() {
        var auth = authenticatorFor(client("s3cret", Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)));
        assertThatThrownBy(() -> auth.authenticate(null, Map.of()))
                .isInstanceOfSatisfying(OAuthException.class,
                        e -> assertThat(e.error()).isEqualTo(OAuthError.INVALID_CLIENT));
    }
}
