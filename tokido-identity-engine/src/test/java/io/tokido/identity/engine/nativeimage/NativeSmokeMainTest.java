package io.tokido.identity.engine.nativeimage;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Covers {@link NativeSmokeMain#run()} and the {@code main()} success path.
 * Testing {@code run()} directly avoids invoking {@link System#exit} while still
 * exercising all engine / Nimbus / RSA paths that the native binary exposes.
 * Testing {@code main()} on the success path covers the try-block wiring.
 */
class NativeSmokeMainTest {

    @Test
    void run_succeeds_with_valid_engine_and_rsa_key() {
        assertThatCode(NativeSmokeMain::run).doesNotThrowAnyException();
    }

    @Test
    void main_returns_normally_on_success_path() {
        // run() succeeds → main prints "native-smoke OK" and returns without System.exit
        assertThatCode(() -> NativeSmokeMain.main(new String[]{})).doesNotThrowAnyException();
    }
}
