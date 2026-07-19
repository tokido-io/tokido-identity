package io.tokido.identity.key;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SigningKeyTest {

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    @Test
    void holds_components() throws Exception {
        KeyPair kp = rsa();
        Instant created = Instant.parse("2026-01-01T00:00:00Z");
        SigningKey k = new SigningKey("kid-1", SignatureAlgorithm.RS256,
                kp.getPrivate(), kp.getPublic(), created, null);
        assertThat(k.kid()).isEqualTo("kid-1");
        assertThat(k.alg()).isEqualTo(SignatureAlgorithm.RS256);
        assertThat(k.privateKey()).isSameAs(kp.getPrivate());
        assertThat(k.publicKey()).isSameAs(kp.getPublic());
        assertThat(k.notAfter()).isNull();
    }

    @Test
    void rejects_blank_kid() throws Exception {
        KeyPair kp = rsa();
        Instant created = Instant.parse("2026-01-01T00:00:00Z");
        assertThatThrownBy(() -> new SigningKey("  ", SignatureAlgorithm.RS256,
                kp.getPrivate(), kp.getPublic(), created, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("kid");
    }

    @Test
    void rejects_nulls() throws Exception {
        KeyPair kp = rsa();
        Instant created = Instant.parse("2026-01-01T00:00:00Z");
        assertThatThrownBy(() -> new SigningKey("k", null,
                kp.getPrivate(), kp.getPublic(), created, null))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new SigningKey("k", SignatureAlgorithm.RS256,
                null, kp.getPublic(), created, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void rejects_notAfter_before_createdAt() throws Exception {
        KeyPair kp = rsa();
        Instant created = Instant.parse("2026-01-01T00:00:00Z");
        assertThatThrownBy(() -> new SigningKey("k", SignatureAlgorithm.RS256,
                kp.getPrivate(), kp.getPublic(), created, created.minusSeconds(1)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("notAfter");
    }
}
