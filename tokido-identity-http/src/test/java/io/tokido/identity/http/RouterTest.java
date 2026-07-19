package io.tokido.identity.http;

import io.tokido.identity.config.DiscoveryConfig;
import io.tokido.identity.engine.IdentityEngine;
import io.tokido.identity.key.KeyStore;
import io.tokido.identity.key.SignatureAlgorithm;
import io.tokido.identity.key.SigningKey;
import io.tokido.identity.key.VerificationKey;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RouterTest {

    private static Router router() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        SigningKey k = new SigningKey("kid-1", SignatureAlgorithm.RS256, kp.getPrivate(), kp.getPublic(),
                Instant.parse("2026-01-01T00:00:00Z"), null);
        KeyStore store = new KeyStore() {
            @Override public SigningKey currentSigningKey() { return k; }
            @Override public List<VerificationKey> verificationKeys() { return List.of(k.toVerificationKey()); }
        };
        IdentityEngine engine = new IdentityEngine(new DiscoveryConfig(URI.create("https://idp.example.com")),
                store, Clock.fixed(Instant.parse("2026-06-26T00:00:00Z"), ZoneOffset.UTC));
        return new Router(engine);
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
    void unbuilt_endpoints_return_501_json() throws Exception {
        Router router = router();
        for (String path : List.of("/authorize", "/token", "/userinfo")) {
            HttpResponse r = router.route(new HttpRequest("GET", path));
            assertThat(r.status()).isEqualTo(HttpStatus.NOT_IMPLEMENTED);
            assertThat(r.headers()).containsEntry("Content-Type", "application/json")
                    .containsEntry("Cache-Control", "no-store");
            assertThat(r.body()).contains("\"error\":\"not_implemented\"");
        }
    }

    @Test
    void unknown_path_returns_404() throws Exception {
        HttpResponse r = router().route(new HttpRequest("GET", "/nope"));
        assertThat(r.status()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(r.headers()).containsEntry("Content-Type", "application/json");
        assertThat(r.body()).contains("\"error\":\"not_found\"");
    }

    @Test
    void wrong_method_on_known_route_returns_405_with_allow() throws Exception {
        Router router = router();
        HttpResponse post = router.route(new HttpRequest("POST", "/jwks"));
        assertThat(post.status()).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED);
        assertThat(post.headers()).containsEntry("Allow", "GET")
                .containsEntry("Content-Type", "application/json");
        HttpResponse delete = router.route(new HttpRequest("DELETE", "/.well-known/openid-configuration"));
        assertThat(delete.status()).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED);
        assertThat(delete.headers()).containsEntry("Allow", "GET");
    }

    @Test
    void any_method_on_unbuilt_endpoint_returns_501() throws Exception {
        // The endpoint's functionality is entirely unimplemented, so 501 is the
        // truthful answer for every method (a POST /token client should learn
        // "not built yet", not "wrong method").
        Router router = router();
        for (String method : List.of("GET", "POST", "PUT")) {
            HttpResponse r = router.route(new HttpRequest(method, "/token"));
            assertThat(r.status()).isEqualTo(HttpStatus.NOT_IMPLEMENTED);
        }
    }

    @Test
    void unknown_path_returns_404_for_any_method() throws Exception {
        Router router = router();
        assertThat(router.route(new HttpRequest("POST", "/nope")).status())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }
}
