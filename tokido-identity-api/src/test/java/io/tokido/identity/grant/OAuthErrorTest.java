package io.tokido.identity.grant;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OAuthErrorTest {

    @Test
    void codes_are_rfc_wire_values() {
        assertThat(OAuthError.INVALID_REQUEST.code()).isEqualTo("invalid_request");
        assertThat(OAuthError.INVALID_CLIENT.code()).isEqualTo("invalid_client");
        assertThat(OAuthError.INVALID_GRANT.code()).isEqualTo("invalid_grant");
        assertThat(OAuthError.UNAUTHORIZED_CLIENT.code()).isEqualTo("unauthorized_client");
        assertThat(OAuthError.UNSUPPORTED_GRANT_TYPE.code()).isEqualTo("unsupported_grant_type");
        assertThat(OAuthError.INVALID_SCOPE.code()).isEqualTo("invalid_scope");
        assertThat(OAuthError.SERVER_ERROR.code()).isEqualTo("server_error");
    }
}
