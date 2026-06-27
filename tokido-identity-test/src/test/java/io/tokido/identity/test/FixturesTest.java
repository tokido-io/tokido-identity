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
}
