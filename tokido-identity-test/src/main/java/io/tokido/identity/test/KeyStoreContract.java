package io.tokido.identity.test;

import io.tokido.identity.key.KeyStore;
import io.tokido.identity.key.SigningKey;
import io.tokido.identity.key.VerificationKey;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Reusable contract any {@link KeyStore} must satisfy. Subclass and implement
 * {@link #createKeyStore()}.
 */
public abstract class KeyStoreContract {

    protected abstract KeyStore createKeyStore();

    @Test
    protected void current_signing_key_is_present() {
        SigningKey k = createKeyStore().currentSigningKey();
        assertThat(k).isNotNull();
        assertThat(k.kid()).isNotBlank();
        assertThat(k.privateKey()).isNotNull();
        assertThat(k.publicKey()).isNotNull();
    }

    @Test
    protected void verification_keys_are_nonempty_and_immutable() {
        var keys = createKeyStore().verificationKeys();
        assertThat(keys).isNotEmpty();
        assertThatThrownBy(() -> keys.add(null)).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    protected void current_key_public_view_is_published() {
        KeyStore store = createKeyStore();
        String kid = store.currentSigningKey().kid();
        assertThat(store.verificationKeys()).extracting(VerificationKey::kid).contains(kid);
        assertThat(store.verificationKeys()).allSatisfy(v -> assertThat(v.publicKey()).isNotNull());
    }
}
