package io.tokido.identity.dev;

import io.tokido.identity.key.SignatureAlgorithm;
import io.tokido.identity.key.SigningKey;
import io.tokido.identity.key.VerificationKey;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InMemoryKeyStoreTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-06-26T00:00:00Z"), ZoneOffset.UTC);

    @Test
    void ephemeral_produces_rs256_key_with_stable_kid() {
        InMemoryKeyStore store = InMemoryKeyStore.ephemeral(CLOCK);
        SigningKey k = store.currentSigningKey();
        assertThat(k.alg()).isEqualTo(SignatureAlgorithm.RS256);
        assertThat(k.kid()).isNotBlank();
        assertThat(store.verificationKeys()).singleElement()
                .satisfies(v -> assertThat(v.kid()).isEqualTo(k.kid()));
        assertThat(k.createdAt()).isEqualTo(Instant.parse("2026-06-26T00:00:00Z"));
    }

    @Test
    void rotate_retains_old_key_in_jwks() {
        InMemoryKeyStore store = InMemoryKeyStore.ephemeral(CLOCK);
        String firstKid = store.currentSigningKey().kid();
        store.rotate();
        String secondKid = store.currentSigningKey().kid();
        assertThat(secondKid).isNotEqualTo(firstKid);
        assertThat(store.verificationKeys()).extracting(v -> v.kid())
                .containsExactlyInAnyOrder(firstKid, secondKid);
    }

    @Test
    void loads_from_pem() throws Exception {
        // Generate a keypair and render PEM to feed fromPem.
        var g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        var kp = g.generateKeyPair();
        String privPem = pem("PRIVATE KEY", kp.getPrivate().getEncoded());
        String pubPem = pem("PUBLIC KEY", kp.getPublic().getEncoded());

        InMemoryKeyStore store = InMemoryKeyStore.fromPem(privPem, pubPem, "pinned-kid", CLOCK);

        assertThat(store.currentSigningKey().kid()).isEqualTo("pinned-kid");
        assertThat(store.currentSigningKey().publicKey().getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    void ephemeral_null_clock_throws() {
        assertThatThrownBy(() -> InMemoryKeyStore.ephemeral(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void fromPem_null_clock_throws() throws Exception {
        var g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        var kp = g.generateKeyPair();
        String privPem = pem("PRIVATE KEY", kp.getPrivate().getEncoded());
        String pubPem = pem("PUBLIC KEY", kp.getPublic().getEncoded());

        assertThatThrownBy(() -> InMemoryKeyStore.fromPem(privPem, pubPem, "kid", null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void fromPem_invalid_base64_throws() {
        assertThatThrownBy(() -> InMemoryKeyStore.fromPem(
                "-----BEGIN PRIVATE KEY-----\ninvalid base64!!!\n-----END PRIVATE KEY-----",
                "-----BEGIN PUBLIC KEY-----\ninvalid base64!!!\n-----END PUBLIC KEY-----",
                "kid",
                CLOCK
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid RSA PEM material");
    }

    @Test
    void verification_keys_contains_current_first() {
        InMemoryKeyStore store = InMemoryKeyStore.ephemeral(CLOCK);
        String currentKid = store.currentSigningKey().kid();
        store.rotate();
        store.rotate();

        List<VerificationKey> keys = store.verificationKeys();
        assertThat(keys).isNotEmpty();
        assertThat(keys.get(0).kid()).isEqualTo(store.currentSigningKey().kid());
    }

    @Test
    void multiple_rotations_retain_all_old_keys() {
        InMemoryKeyStore store = InMemoryKeyStore.ephemeral(CLOCK);
        String kid1 = store.currentSigningKey().kid();
        store.rotate();
        String kid2 = store.currentSigningKey().kid();
        store.rotate();
        String kid3 = store.currentSigningKey().kid();

        List<VerificationKey> keys = store.verificationKeys();
        assertThat(keys).hasSize(3)
                .extracting(VerificationKey::kid)
                .containsExactlyInAnyOrder(kid1, kid2, kid3);
    }

    @Test
    void pem_kid_is_pinned() throws Exception {
        var g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        var kp = g.generateKeyPair();
        String privPem = pem("PRIVATE KEY", kp.getPrivate().getEncoded());
        String pubPem = pem("PUBLIC KEY", kp.getPublic().getEncoded());

        InMemoryKeyStore store1 = InMemoryKeyStore.fromPem(privPem, pubPem, "custom-kid", CLOCK);
        InMemoryKeyStore store2 = InMemoryKeyStore.fromPem(privPem, pubPem, "another-kid", CLOCK);

        assertThat(store1.currentSigningKey().kid()).isEqualTo("custom-kid");
        assertThat(store2.currentSigningKey().kid()).isEqualTo("another-kid");
    }

    private static String pem(String label, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
    }
}
