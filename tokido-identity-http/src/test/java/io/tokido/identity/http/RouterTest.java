package io.tokido.identity.http;

import io.tokido.identity.client.ClientAuthenticationMethod;
import io.tokido.identity.client.ClientStore;
import io.tokido.identity.client.RegisteredClient;
import io.tokido.identity.config.DiscoveryConfig;
import io.tokido.identity.engine.IdentityEngine;
import io.tokido.identity.engine.client.Pbkdf2SecretHasher;
import io.tokido.identity.engine.signing.NimbusTokenSigner;
import io.tokido.identity.key.KeyStore;
import io.tokido.identity.key.SignatureAlgorithm;
import io.tokido.identity.key.SigningKey;
import io.tokido.identity.key.VerificationKey;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RouterTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-06-26T00:00:00Z"), ZoneOffset.UTC);
    private static final Pbkdf2SecretHasher HASHER = new Pbkdf2SecretHasher(10_000);

    private static KeyStore keyStore() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        SigningKey k = new SigningKey("kid-1", SignatureAlgorithm.RS256, kp.getPrivate(), kp.getPublic(),
                Instant.parse("2026-01-01T00:00:00Z"), null);
        return new KeyStore() {
            @Override public SigningKey currentSigningKey() { return k; }
            @Override public List<VerificationKey> verificationKeys() { return List.of(k.toVerificationKey()); }
        };
    }

    /** Discovery/JWKS-only router (no token endpoint). */
    private static Router router() throws Exception {
        IdentityEngine engine = new IdentityEngine(
                new DiscoveryConfig(URI.create("https://idp.example.com")), keyStore(), CLOCK);
        return new Router(engine);
    }

    /** Fully-wired router with a demo confidential client. */
    private static Router tokenRouter() throws Exception {
        RegisteredClient client = new RegisteredClient("c1", HASHER.hash("s3cret"),
                Set.of("client_credentials"), Set.of("read", "write"),
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST));
        ClientStore store = id -> "c1".equals(id) ? Optional.of(client) : Optional.empty();
        IdentityEngine engine = IdentityEngine.builder()
                .discoveryConfig(new DiscoveryConfig(URI.create("https://idp.example.com")))
                .keyStore(keyStore()).clock(CLOCK)
                .tokenSigner(new NimbusTokenSigner()).clientStore(store).secretHasher(HASHER)
                .build();
        return new Router(engine);
    }

    private static HttpRequest post(String path, String authHeader, Map<String, String> form) {
        Map<String, String> headers = authHeader == null ? Map.of() : Map.of("Authorization", authHeader);
        return new HttpRequest("POST", path, headers, form);
    }

    private static String basic(String id, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void serves_discovery() throws Exception {
        HttpResponse r = router().route(new HttpRequest("GET", "/.well-known/openid-configuration"));
        assertThat(r.status()).isEqualTo(HttpStatus.OK);
        assertThat(r.headers()).containsEntry("Content-Type", "application/json")
                .containsEntry("Cache-Control", "public, max-age=300");
        assertThat(r.body()).contains("\"issuer\":\"https://idp.example.com\"");
    }

    @Test
    void serves_jwks() throws Exception {
        HttpResponse r = router().route(new HttpRequest("GET", "/jwks"));
        assertThat(r.status()).isEqualTo(HttpStatus.OK);
        assertThat(r.headers()).containsEntry("Cache-Control", "public, max-age=300");
        assertThat(r.body()).contains("\"keys\"").contains("\"kid\":\"kid-1\"");
    }

    @Test
    void authorize_and_userinfo_return_501_for_any_method() throws Exception {
        Router router = router();
        for (String path : List.of("/authorize", "/userinfo")) {
            for (String method : List.of("GET", "POST", "PUT")) {
                HttpResponse r = router.route(new HttpRequest(method, path));
                assertThat(r.status()).isEqualTo(HttpStatus.NOT_IMPLEMENTED);
                assertThat(r.body()).contains("\"error\":\"not_implemented\"");
            }
        }
    }

    @Test
    void unknown_path_returns_404() throws Exception {
        HttpResponse r = router().route(new HttpRequest("GET", "/nope"));
        assertThat(r.status()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(r.body()).contains("\"error\":\"not_found\"");
    }

    @Test
    void wrong_method_on_get_route_returns_405_with_allow_get() throws Exception {
        Router router = router();
        HttpResponse post = router.route(new HttpRequest("POST", "/jwks"));
        assertThat(post.status()).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED);
        assertThat(post.headers()).containsEntry("Allow", "GET");
    }

    @Test
    void get_token_returns_405_with_allow_post() throws Exception {
        HttpResponse r = tokenRouter().route(new HttpRequest("GET", "/token"));
        assertThat(r.status()).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED);
        assertThat(r.headers()).containsEntry("Allow", "POST").containsEntry("Cache-Control", "no-store");
    }

    @Test
    void post_token_issues_signed_scoped_token() throws Exception {
        HttpResponse r = tokenRouter().route(post("/token", basic("c1", "s3cret"),
                Map.of("grant_type", "client_credentials", "scope", "read")));
        assertThat(r.status()).isEqualTo(HttpStatus.OK);
        assertThat(r.headers()).containsEntry("Cache-Control", "no-store").containsEntry("Pragma", "no-cache");
        assertThat(r.body())
                .contains("\"access_token\":")
                .contains("\"token_type\":\"Bearer\"")
                .contains("\"expires_in\":3600")
                .contains("\"scope\":\"read\"");
    }

    @Test
    void post_token_bad_secret_via_basic_returns_401_with_challenge() throws Exception {
        HttpResponse r = tokenRouter().route(post("/token", basic("c1", "WRONG"),
                Map.of("grant_type", "client_credentials")));
        assertThat(r.status()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(r.headers()).containsEntry("WWW-Authenticate", "Basic").containsEntry("Cache-Control", "no-store");
        assertThat(r.body()).contains("\"error\":\"invalid_client\"");
    }

    @Test
    void post_token_bad_secret_via_post_returns_400_no_challenge() throws Exception {
        HttpResponse r = tokenRouter().route(post("/token", null,
                Map.of("grant_type", "client_credentials", "client_id", "c1", "client_secret", "WRONG")));
        assertThat(r.status()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(r.headers()).doesNotContainKey("WWW-Authenticate");
        assertThat(r.body()).contains("\"error\":\"invalid_client\"");
    }

    @Test
    void post_token_unsupported_grant_returns_400() throws Exception {
        HttpResponse r = tokenRouter().route(post("/token", basic("c1", "s3cret"),
                Map.of("grant_type", "password")));
        assertThat(r.status()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(r.body()).contains("\"error\":\"unsupported_grant_type\"");
    }

    @Test
    void unknown_path_returns_404_for_any_method() throws Exception {
        assertThat(router().route(new HttpRequest("POST", "/nope")).status())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }
}
