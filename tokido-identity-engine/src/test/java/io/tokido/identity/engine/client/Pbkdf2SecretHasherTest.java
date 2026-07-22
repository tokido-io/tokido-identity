package io.tokido.identity.engine.client;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class Pbkdf2SecretHasherTest {

    private final Pbkdf2SecretHasher hasher = new Pbkdf2SecretHasher(10_000); // lower cost for fast tests

    @Test
    void hash_is_self_describing() {
        assertThat(hasher.hash("s3cret")).startsWith("pbkdf2-sha256$10000$");
    }

    @Test
    void hashing_same_secret_twice_differs_due_to_random_salt() {
        assertThat(hasher.hash("s3cret")).isNotEqualTo(hasher.hash("s3cret"));
    }

    @Test
    void matches_accepts_correct_secret() {
        String stored = hasher.hash("s3cret");
        assertThat(hasher.matches("s3cret", stored)).isTrue();
    }

    @Test
    void matches_rejects_wrong_secret() {
        String stored = hasher.hash("s3cret");
        assertThat(hasher.matches("wrong", stored)).isFalse();
    }

    @Test
    void matches_across_different_hashes_of_different_secrets() {
        assertThat(hasher.matches("a", hasher.hash("b"))).isFalse();
    }

    @Test
    void matches_returns_false_for_malformed_hash() {
        assertThat(hasher.matches("s3cret", "not-a-valid-hash")).isFalse();
        assertThat(hasher.matches("s3cret", "pbkdf2-sha256$notanumber$xx$yy")).isFalse();
        assertThat(hasher.matches("s3cret", null)).isFalse();
    }

    @Test
    void verification_works_across_hasher_instances_with_default_cost() {
        Pbkdf2SecretHasher a = new Pbkdf2SecretHasher();
        Pbkdf2SecretHasher b = new Pbkdf2SecretHasher();
        assertThat(b.matches("shared", a.hash("shared"))).isTrue();
    }
}
