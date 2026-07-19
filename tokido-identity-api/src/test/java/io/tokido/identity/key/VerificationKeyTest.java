package io.tokido.identity.key;

import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VerificationKeyTest {

    private static PublicKey rsaPublic() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair().getPublic();
    }

    @Test
    void holds_components() throws Exception {
        PublicKey pub = rsaPublic();
        Instant created = Instant.parse("2026-01-01T00:00:00Z");
        VerificationKey k = new VerificationKey("kid-1", SignatureAlgorithm.RS256, pub, created, null);
        assertThat(k.kid()).isEqualTo("kid-1");
        assertThat(k.publicKey()).isSameAs(pub);
    }

    @Test
    void rejects_blank_kid() throws Exception {
        PublicKey pub = rsaPublic();
        Instant created = Instant.parse("2026-01-01T00:00:00Z");
        assertThatThrownBy(() -> new VerificationKey(" ", SignatureAlgorithm.RS256, pub, created, null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
