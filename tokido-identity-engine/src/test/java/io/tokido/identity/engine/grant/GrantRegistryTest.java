package io.tokido.identity.engine.grant;

import io.tokido.identity.grant.GrantContext;
import io.tokido.identity.grant.GrantHandler;
import io.tokido.identity.grant.OAuthError;
import io.tokido.identity.grant.OAuthException;
import io.tokido.identity.grant.TokenResponse;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GrantRegistryTest {

    private static GrantHandler handlerFor(String grantType) {
        return new GrantHandler() {
            @Override
            public String grantType() {
                return grantType;
            }

            @Override
            public TokenResponse handle(GrantContext context) {
                throw new UnsupportedOperationException();
            }
        };
    }

    @Test
    void resolves_registered_handler() {
        GrantHandler cc = new ClientCredentialsGrantHandler();
        GrantRegistry registry = new GrantRegistry(List.of(cc));
        assertThat(registry.get("client_credentials")).isSameAs(cc);
    }

    @Test
    void unknown_grant_type_is_unsupported_grant_type() {
        GrantRegistry registry = new GrantRegistry(List.of(new ClientCredentialsGrantHandler()));
        assertThatThrownBy(() -> registry.get("password"))
                .isInstanceOfSatisfying(OAuthException.class,
                        e -> assertThat(e.error()).isEqualTo(OAuthError.UNSUPPORTED_GRANT_TYPE));
    }

    @Test
    void duplicate_grant_types_are_rejected() {
        assertThatThrownBy(() -> new GrantRegistry(List.of(handlerFor("dup"), handlerFor("dup"))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void grant_types_are_reported_sorted() {
        GrantRegistry registry = new GrantRegistry(List.of(handlerFor("refresh_token"), handlerFor("client_credentials")));
        assertThat(registry.grantTypes()).containsExactly("client_credentials", "refresh_token");
    }
}
