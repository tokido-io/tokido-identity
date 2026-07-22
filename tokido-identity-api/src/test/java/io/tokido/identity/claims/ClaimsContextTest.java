package io.tokido.identity.claims;

import io.tokido.identity.client.ClientAuthenticationMethod;
import io.tokido.identity.client.RegisteredClient;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClaimsContextTest {

    private static final RegisteredClient CLIENT = new RegisteredClient("c1", "h",
            Set.of("client_credentials"), Set.of("read"),
            Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));

    @Test
    void holds_targeting_components() {
        ClaimsContext ctx = new ClaimsContext("access_token", "client_credentials", CLIENT, "c1", Set.of("read"));
        assertThat(ctx.tokenType()).isEqualTo("access_token");
        assertThat(ctx.grantType()).isEqualTo("client_credentials");
        assertThat(ctx.client()).isSameAs(CLIENT);
        assertThat(ctx.subject()).isEqualTo("c1");
        assertThat(ctx.scopes()).containsExactly("read");
    }

    @Test
    void scopes_are_immutable() {
        ClaimsContext ctx = new ClaimsContext("access_token", "client_credentials", CLIENT, "c1", Set.of("read"));
        assertThatThrownBy(() -> ctx.scopes().add("write"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void rejects_invalid_fields() {
        assertThatThrownBy(() -> new ClaimsContext(" ", "g", CLIENT, "c1", Set.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ClaimsContext("access_token", "g", CLIENT, " ", Set.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatNullPointerException()
                .isThrownBy(() -> new ClaimsContext("access_token", "g", null, "c1", Set.of()));
    }
}
