package io.tokido.identity.key;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class KeyStoreTest {

    private static SigningKey newKey(String kid) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        return new SigningKey(kid, SignatureAlgorithm.RS256, kp.getPrivate(), kp.getPublic(),
                Instant.parse("2026-01-01T00:00:00Z"), null);
    }

    @Test
    void exposes_current_and_verification_keys() throws Exception {
        SigningKey current = newKey("kid-1");
        KeyStore store = new KeyStore() {
            @Override public SigningKey currentSigningKey() { return current; }
            @Override public List<VerificationKey> verificationKeys() {
                return List.of(current.toVerificationKey());
            }
        };
        assertThat(store.currentSigningKey().kid()).isEqualTo("kid-1");
        assertThat(store.verificationKeys()).singleElement()
                .extracting(VerificationKey::kid).isEqualTo("kid-1");
    }
}
