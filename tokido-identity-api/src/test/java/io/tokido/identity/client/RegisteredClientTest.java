package io.tokido.identity.client;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RegisteredClientTest {

    private static RegisteredClient valid() {
        return new RegisteredClient("c1", "hash:abc",
                Set.of("client_credentials"), Set.of("read", "write"),
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
    }

    @Test
    void constructs_and_round_trips() {
        RegisteredClient c = valid();
        assertThat(c.clientId()).isEqualTo("c1");
        assertThat(c.secretHash()).isEqualTo("hash:abc");
        assertThat(c.allowedGrantTypes()).containsExactly("client_credentials");
        assertThat(c.allowedScopes()).containsExactlyInAnyOrder("read", "write");
        assertThat(c.tokenEndpointAuthMethods())
                .containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    @Test
    void collections_are_immutable() {
        assertThatThrownBy(() -> valid().allowedScopes().add("admin"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void rejects_null_and_blank_client_id() {
        assertThatNullPointerException().isThrownBy(() -> new RegisteredClient(
                null, "h", Set.of(), Set.of(), Set.of()));
        assertThatThrownBy(() -> new RegisteredClient(" ", "h", Set.of(), Set.of(), Set.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejects_null_and_blank_secret_hash() {
        assertThatNullPointerException().isThrownBy(() -> new RegisteredClient(
                "c1", null, Set.of(), Set.of(), Set.of()));
        assertThatThrownBy(() -> new RegisteredClient("c1", "", Set.of(), Set.of(), Set.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejects_null_collections() {
        assertThatNullPointerException().isThrownBy(() -> new RegisteredClient(
                "c1", "h", null, Set.of(), Set.of()));
    }
}
