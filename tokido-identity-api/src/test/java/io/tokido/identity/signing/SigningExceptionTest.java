package io.tokido.identity.signing;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SigningExceptionTest {
    @Test
    void wraps_message_and_cause() {
        Throwable cause = new IllegalStateException("boom");
        SigningException ex = new SigningException("sign failed", cause);
        assertThat(ex).hasMessage("sign failed").hasCause(cause);
        assertThat(new SigningException("only message")).hasMessage("only message");
    }
}
