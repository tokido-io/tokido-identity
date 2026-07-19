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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class JsonTest {
    @Test
    void writes_ordered_object() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("issuer", "https://idp");
        m.put("flag", false);
        String json = Json.write(m);
        assertThat(json).contains("\"issuer\":\"https://idp\"").contains("\"flag\":false");
    }

    @Test
    void writes_jwk_set() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        SigningKey key = new SigningKey("test-kid", SignatureAlgorithm.RS256, kp.getPrivate(),
                kp.getPublic(), Instant.parse("2026-01-01T00:00:00Z"), null);
        KeyStore store = new KeyStore() {
            @Override public SigningKey currentSigningKey() { return key; }
            @Override public List<VerificationKey> verificationKeys() {
                return List.of(key.toVerificationKey());
            }
        };

        JsonWebKeySet set = Jwks.from(store);
        String json = Json.write(set);

        assertThat(json).contains("\"keys\"").contains("\"kty\":\"RSA\"").contains("\"use\":\"sig\"");
        assertThat(json).contains("\"alg\":\"RS256\"").contains("\"kid\":\"test-kid\"");
    }
}
