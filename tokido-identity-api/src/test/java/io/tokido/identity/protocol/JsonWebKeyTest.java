package io.tokido.identity.protocol;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JsonWebKeyTest {

    private static Map<String, Object> publicRsa() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kty", "RSA");
        m.put("use", "sig");
        m.put("alg", "RS256");
        m.put("kid", "kid-1");
        m.put("n", "0vx7...");
        m.put("e", "AQAB");
        return m;
    }

    @Test
    void accepts_public_jwk() {
        JsonWebKey jwk = new JsonWebKey(publicRsa());
        assertThat(jwk.members()).containsEntry("kty", "RSA").containsEntry("kid", "kid-1");
    }

    @ParameterizedTest
    @ValueSource(strings = {"d", "p", "q", "dp", "dq", "qi", "k"})
    void rejects_private_params(String param) {
        Map<String, Object> m = publicRsa();
        m.put(param, "PRIVATE");
        assertThatThrownBy(() -> new JsonWebKey(m))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("private");
    }

    @Test
    void requires_kty_and_kid() {
        Map<String, Object> m = publicRsa();
        m.remove("kid");
        assertThatThrownBy(() -> new JsonWebKey(m)).isInstanceOf(IllegalArgumentException.class);

        Map<String, Object> m2 = publicRsa();
        m2.remove("kty");
        assertThatThrownBy(() -> new JsonWebKey(m2)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void members_are_immutable_copy() {
        Map<String, Object> src = publicRsa();
        JsonWebKey jwk = new JsonWebKey(src);
        src.put("n", "mutated");
        assertThat(jwk.members()).containsEntry("n", "0vx7...");
        assertThatThrownBy(() -> jwk.members().put("x", "y"))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
