package io.tokido.identity.grant;

import io.tokido.identity.client.ClientAuthenticationMethod;
import io.tokido.identity.client.RegisteredClient;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class GrantContextTest {

    private static final RegisteredClient CLIENT = new RegisteredClient("c1", "h",
            Set.of("client_credentials"), Set.of("read"),
            Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
    private static final TokenRequest REQUEST =
            new TokenRequest("client_credentials", Set.of("read"), Map.of());
    private static final TokenMinter MINTER = req -> {
        throw new UnsupportedOperationException("not used");
    };

    @Test
    void holds_components() {
        GrantContext ctx = new GrantContext(REQUEST, CLIENT, MINTER);
        assertThat(ctx.request()).isSameAs(REQUEST);
        assertThat(ctx.client()).isSameAs(CLIENT);
        assertThat(ctx.minter()).isSameAs(MINTER);
    }

    @Test
    void rejects_nulls() {
        assertThatNullPointerException().isThrownBy(() -> new GrantContext(null, CLIENT, MINTER));
        assertThatNullPointerException().isThrownBy(() -> new GrantContext(REQUEST, null, MINTER));
        assertThatNullPointerException().isThrownBy(() -> new GrantContext(REQUEST, CLIENT, null));
    }
}
