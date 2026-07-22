package io.tokido.identity.engine;

import com.nimbusds.jwt.SignedJWT;
import io.tokido.identity.client.ClientAuthenticationMethod;
import io.tokido.identity.client.ClientStore;
import io.tokido.identity.client.RegisteredClient;
import io.tokido.identity.config.DiscoveryConfig;
import io.tokido.identity.engine.client.Pbkdf2SecretHasher;
import io.tokido.identity.engine.grant.TokenResult;
import io.tokido.identity.engine.signing.NimbusTokenSigner;
import io.tokido.identity.grant.OAuthError;
import io.tokido.identity.key.KeyStore;
import io.tokido.identity.test.Fixtures;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenEndpointTest {

    private final Pbkdf2SecretHasher hasher = new Pbkdf2SecretHasher(10_000);
    private final KeyStore keyStore = Fixtures.singleKeyStore(Fixtures.rsaSigningKey("kid-1"));

    private final RegisteredClient client = new RegisteredClient("c1", hasher.hash("s3cret"),
            Set.of("client_credentials"), Set.of("read", "write"),
            Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST));

    private final ClientStore clientStore =
            id -> "c1".equals(id) ? Optional.of(client) : Optional.empty();

    private IdentityEngine engine() {
        return IdentityEngine.builder()
                .discoveryConfig(new DiscoveryConfig(URI.create("https://idp.example.com")))
                .keyStore(keyStore)
                .clock(Fixtures.fixedClock())
                .tokenSigner(new NimbusTokenSigner())
                .clientStore(clientStore)
                .secretHasher(hasher)
                .build();
    }

    private static String basic(String id, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void issues_signed_scoped_token_via_basic() throws Exception {
        TokenResult result = engine().token(basic("c1", "s3cret"),
                Map.of("grant_type", "client_credentials", "scope", "read"));

        assertThat(result).isInstanceOf(TokenResult.Success.class);
        var response = ((TokenResult.Success) result).response();
        assertThat(response.scope()).containsExactly("read");
        var claims = SignedJWT.parse(response.accessToken()).getJWTClaimsSet();
        assertThat(claims.getStringClaim("client_id")).isEqualTo("c1");
        assertThat(claims.getStringClaim("scope")).isEqualTo("read");
        assertThat(claims.getAudience()).containsExactly("https://idp.example.com"); // default audience = issuer
    }

    @Test
    void issues_token_via_post() {
        TokenResult result = engine().token(null,
                Map.of("grant_type", "client_credentials", "client_id", "c1", "client_secret", "s3cret"));
        assertThat(result).isInstanceOf(TokenResult.Success.class);
    }

    @Test
    void missing_credentials_is_invalid_client() {
        TokenResult result = engine().token(null, Map.of("grant_type", "client_credentials"));
        assertThat(result).isInstanceOfSatisfying(TokenResult.Error.class, e -> {
            assertThat(e.error()).isEqualTo(OAuthError.INVALID_CLIENT);
            assertThat(e.basicChallenge()).isFalse();
        });
    }

    @Test
    void bad_secret_via_basic_is_invalid_client_with_challenge() {
        TokenResult result = engine().token(basic("c1", "WRONG"),
                Map.of("grant_type", "client_credentials"));
        assertThat(result).isInstanceOfSatisfying(TokenResult.Error.class, e -> {
            assertThat(e.error()).isEqualTo(OAuthError.INVALID_CLIENT);
            assertThat(e.basicChallenge()).isTrue();
        });
    }

    @Test
    void unknown_grant_after_authentication_is_unsupported_grant_type() {
        TokenResult result = engine().token(basic("c1", "s3cret"), Map.of("grant_type", "password"));
        assertThat(result).isInstanceOfSatisfying(TokenResult.Error.class,
                e -> assertThat(e.error()).isEqualTo(OAuthError.UNSUPPORTED_GRANT_TYPE));
    }

    @Test
    void missing_grant_type_is_invalid_request() {
        TokenResult result = engine().token(basic("c1", "s3cret"), Map.of());
        assertThat(result).isInstanceOfSatisfying(TokenResult.Error.class,
                e -> assertThat(e.error()).isEqualTo(OAuthError.INVALID_REQUEST));
    }

    @Test
    void discovery_reports_feature_derived_capabilities() {
        String json = engine().discoveryJson();
        assertThat(json).contains("\"grant_types_supported\":[\"client_credentials\"]");
        assertThat(json).contains(
                "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"]");
        assertThat(json).doesNotContain("authorization_code");
    }

    @Test
    void discovery_only_engine_rejects_token_calls() {
        IdentityEngine discoveryOnly = new IdentityEngine(
                new DiscoveryConfig(URI.create("https://idp.example.com")), keyStore, Fixtures.fixedClock());
        assertThatThrownBy(() -> discoveryOnly.token(null, Map.of()))
                .isInstanceOf(IllegalStateException.class);
    }
}
