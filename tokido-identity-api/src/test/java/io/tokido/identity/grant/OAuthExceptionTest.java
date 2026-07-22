package io.tokido.identity.grant;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class OAuthExceptionTest {

    @Test
    void carries_error_description_and_basic_challenge() {
        OAuthException e = new OAuthException(OAuthError.INVALID_CLIENT, "bad credentials", true);
        assertThat(e.error()).isEqualTo(OAuthError.INVALID_CLIENT);
        assertThat(e.getMessage()).isEqualTo("bad credentials");
        assertThat(e.basicChallenge()).isTrue();
    }

    @Test
    void two_arg_constructor_defaults_no_basic_challenge() {
        OAuthException e = new OAuthException(OAuthError.INVALID_SCOPE, "scope too wide");
        assertThat(e.basicChallenge()).isFalse();
        assertThat(e.error()).isEqualTo(OAuthError.INVALID_SCOPE);
    }

    @Test
    void rejects_null_error() {
        assertThatNullPointerException()
                .isThrownBy(() -> new OAuthException(null, "desc"));
    }
}
