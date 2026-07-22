package io.tokido.identity.client;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientAuthenticationMethodTest {

    @Test
    void wire_values_are_lowercase_names() {
        assertThat(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.wireValue()).isEqualTo("client_secret_basic");
        assertThat(ClientAuthenticationMethod.CLIENT_SECRET_POST.wireValue()).isEqualTo("client_secret_post");
    }

    @Test
    void from_wire_resolves_known_values() {
        assertThat(ClientAuthenticationMethod.fromWire("client_secret_basic"))
                .isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(ClientAuthenticationMethod.fromWire("client_secret_post"))
                .isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_POST);
    }

    @Test
    void from_wire_rejects_unknown() {
        assertThatThrownBy(() -> ClientAuthenticationMethod.fromWire("private_key_jwt"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void from_wire_rejects_null() {
        assertThatNullPointerException().isThrownBy(() -> ClientAuthenticationMethod.fromWire(null));
    }
}
