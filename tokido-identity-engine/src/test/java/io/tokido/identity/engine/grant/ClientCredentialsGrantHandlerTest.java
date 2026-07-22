package io.tokido.identity.engine.grant;

import io.tokido.identity.client.ClientAuthenticationMethod;
import io.tokido.identity.client.RegisteredClient;
import io.tokido.identity.grant.AccessTokenRequest;
import io.tokido.identity.grant.GrantContext;
import io.tokido.identity.grant.MintedToken;
import io.tokido.identity.grant.OAuthError;
import io.tokido.identity.grant.OAuthException;
import io.tokido.identity.grant.TokenRequest;
import io.tokido.identity.grant.TokenResponse;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientCredentialsGrantHandlerTest {

    private static final Instant IAT = Instant.parse("2026-06-26T00:00:00Z");
    private final ClientCredentialsGrantHandler handler = new ClientCredentialsGrantHandler();
    private final AtomicReference<AccessTokenRequest> minted = new AtomicReference<>();

    private RegisteredClient client(Set<String> grants, Set<String> scopes) {
        return new RegisteredClient("c1", "hash", grants, scopes,
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
    }

    private GrantContext context(RegisteredClient client, Set<String> requestedScopes) {
        TokenRequest req = new TokenRequest("client_credentials", requestedScopes, Map.of());
        return new GrantContext(req, client, request -> {
            minted.set(request);
            return new MintedToken("jws.value.here", IAT, IAT.plusSeconds(3600));
        });
    }

    @Test
    void grant_type_is_client_credentials() {
        assertThat(handler.grantType()).isEqualTo("client_credentials");
    }

    @Test
    void narrows_requested_scope_and_mints() {
        RegisteredClient c = client(Set.of("client_credentials"), Set.of("read", "write"));
        TokenResponse resp = handler.handle(context(c, Set.of("read")));

        assertThat(resp.accessToken()).isEqualTo("jws.value.here");
        assertThat(resp.tokenType()).isEqualTo("Bearer");
        assertThat(resp.expiresIn()).isEqualTo(Duration.ofHours(1));
        assertThat(resp.scope()).containsExactly("read");
        assertThat(minted.get().subject()).isEqualTo("c1");
        assertThat(minted.get().client()).isSameAs(c);
        assertThat(minted.get().scopes()).containsExactly("read");
        assertThat(minted.get().grantType()).isEqualTo("client_credentials");
    }

    @Test
    void empty_request_grants_full_allowed_set() {
        RegisteredClient c = client(Set.of("client_credentials"), Set.of("read", "write"));
        TokenResponse resp = handler.handle(context(c, Set.of()));
        assertThat(resp.scope()).containsExactlyInAnyOrder("read", "write");
    }

    @Test
    void requesting_disallowed_scope_is_invalid_scope() {
        RegisteredClient c = client(Set.of("client_credentials"), Set.of("read"));
        assertThatThrownBy(() -> handler.handle(context(c, Set.of("read", "admin"))))
                .isInstanceOfSatisfying(OAuthException.class,
                        e -> assertThat(e.error()).isEqualTo(OAuthError.INVALID_SCOPE));
    }

    @Test
    void client_not_allowed_grant_is_unauthorized_client() {
        RegisteredClient c = client(Set.of("authorization_code"), Set.of("read"));
        assertThatThrownBy(() -> handler.handle(context(c, Set.of("read"))))
                .isInstanceOfSatisfying(OAuthException.class,
                        e -> assertThat(e.error()).isEqualTo(OAuthError.UNAUTHORIZED_CLIENT));
    }
}
