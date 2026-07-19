package io.tokido.identity.engine;

import io.tokido.identity.config.DiscoveryConfig;
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

class IdentityEngineTest {

    private static IdentityEngine engine() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        SigningKey k = new SigningKey("kid-1", SignatureAlgorithm.RS256, kp.getPrivate(), kp.getPublic(),
                Instant.parse("2026-01-01T00:00:00Z"), null);
        KeyStore store = new KeyStore() {
            @Override public SigningKey currentSigningKey() { return k; }
            @Override public List<VerificationKey> verificationKeys() { return List.of(k.toVerificationKey()); }
        };
        Clock clock = Clock.fixed(Instant.parse("2026-06-26T00:00:00Z"), ZoneOffset.UTC);
        return new IdentityEngine(new DiscoveryConfig(URI.create("https://idp.example.com")), store, clock);
    }

    @Test
    void serves_discovery_json() throws Exception {
        String json = engine().discoveryJson();
        assertThat(json).contains("\"issuer\":\"https://idp.example.com\"")
                .contains("\"jwks_uri\":\"https://idp.example.com/jwks\"")
                .contains("\"id_token_signing_alg_values_supported\":[\"RS256\"]")
                .contains("\"request_uri_parameter_supported\":false");
    }

    @Test
    void serves_jwks_json_without_private_params() throws Exception {
        String json = engine().jwksJson();
        assertThat(json).contains("\"keys\"").contains("\"kid\":\"kid-1\"").contains("\"use\":\"sig\"");
        assertThat(json).doesNotContain("\"d\":");
    }

    @Test
    void exposes_injected_clock() throws Exception {
        assertThat(engine().clock().instant()).isEqualTo(Instant.parse("2026-06-26T00:00:00Z"));
    }

    @Test
    void constructor_rejects_nulls() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        SigningKey k = new SigningKey("kid-1", SignatureAlgorithm.RS256, kp.getPrivate(), kp.getPublic(),
                Instant.parse("2026-01-01T00:00:00Z"), null);
        KeyStore store = new KeyStore() {
            @Override public SigningKey currentSigningKey() { return k; }
            @Override public List<VerificationKey> verificationKeys() { return List.of(k.toVerificationKey()); }
        };
        DiscoveryConfig cfg = new DiscoveryConfig(URI.create("https://idp.example.com"));
        Clock clock = Clock.fixed(Instant.parse("2026-06-26T00:00:00Z"), ZoneOffset.UTC);

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new IdentityEngine(null, store, clock))
                .isInstanceOf(NullPointerException.class).hasMessageContaining("config");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new IdentityEngine(cfg, null, clock))
                .isInstanceOf(NullPointerException.class).hasMessageContaining("keyStore");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new IdentityEngine(cfg, store, null))
                .isInstanceOf(NullPointerException.class).hasMessageContaining("clock");
    }
}
