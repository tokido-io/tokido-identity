package io.tokido.identity.test;

import io.tokido.identity.key.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class FixturesTest {
    @Test
    void fixed_clock_is_deterministic() {
        assertThat(Fixtures.fixedClock().instant()).isEqualTo(Instant.parse("2026-06-26T00:00:00Z"));
    }

    @Test
    void rsa_signing_key_and_single_store() {
        var key = Fixtures.rsaSigningKey("kid-x");
        assertThat(key.alg()).isEqualTo(SignatureAlgorithm.RS256);
        var store = Fixtures.singleKeyStore(key);
        assertThat(store.currentSigningKey().kid()).isEqualTo("kid-x");
        assertThat(store.verificationKeys()).singleElement()
                .satisfies(v -> assertThat(v.kid()).isEqualTo("kid-x"));
    }

    @Test
    void stub_secret_hasher_round_trips() {
        var hasher = Fixtures.stubSecretHasher();
        assertThat(hasher.hash("secret")).isEqualTo("stub:secret");
        assertThat(hasher.matches("secret", "stub:secret")).isTrue();
        assertThat(hasher.matches("wrong", "stub:secret")).isFalse();
    }

    @Test
    void demo_client_permits_client_credentials() {
        var client = Fixtures.demoClient(Fixtures.stubSecretHasher());
        assertThat(client.clientId()).isEqualTo("demo-client");
        assertThat(client.allowedGrantTypes()).contains("client_credentials");
        assertThat(client.secretHash()).isEqualTo("stub:demo-secret");
    }
}
