package io.tokido.identity.engine;

import io.tokido.identity.key.KeyStore;
import io.tokido.identity.key.SignatureAlgorithm;
import io.tokido.identity.key.SigningKey;
import io.tokido.identity.key.VerificationKey;
import io.tokido.identity.protocol.JsonWebKeySet;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JwksTest {

    private static SigningKey key(String kid) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        return new SigningKey(kid, SignatureAlgorithm.RS256, kp.getPrivate(), kp.getPublic(),
                Instant.parse("2026-01-01T00:00:00Z"), null);
    }

    @Test
    void builds_public_jwk_set_from_keystore() throws Exception {
        SigningKey k1 = key("kid-1");
        SigningKey k2 = key("kid-2");
        KeyStore store = new KeyStore() {
            @Override public SigningKey currentSigningKey() { return k1; }
            @Override public List<VerificationKey> verificationKeys() {
                return List.of(k1.toVerificationKey(), k2.toVerificationKey());
            }
        };

        JsonWebKeySet set = Jwks.from(store);

        assertThat(set.keys()).hasSize(2);
        assertThat(set.keys()).allSatisfy(jwk -> {
            assertThat(jwk.members()).containsEntry("kty", "RSA")
                    .containsEntry("use", "sig").containsEntry("alg", "RS256");
            assertThat(jwk.members()).containsKey("n").containsKey("e");
            assertThat(jwk.members()).doesNotContainKeys("d", "p", "q");
        });
        assertThat(set.keys().stream().map(j -> j.members().get("kid")))
                .containsExactlyInAnyOrder("kid-1", "kid-2");
    }
}
