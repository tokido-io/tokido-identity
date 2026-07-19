package io.tokido.identity.test;

import io.tokido.identity.key.KeyStore;
import io.tokido.identity.key.SignatureAlgorithm;
import io.tokido.identity.key.SigningKey;
import io.tokido.identity.key.VerificationKey;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

/** Reusable test fixtures for framework and plugin authors. */
public final class Fixtures {

    /** A deterministic clock fixed at 2026-06-26T00:00:00Z. */
    public static Clock fixedClock() {
        return Clock.fixed(Instant.parse("2026-06-26T00:00:00Z"), ZoneOffset.UTC);
    }

    /** A fresh RS256 signing key with the given kid. */
    public static SigningKey rsaSigningKey(String kid) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            KeyPair kp = g.generateKeyPair();
            return new SigningKey(kid, SignatureAlgorithm.RS256, kp.getPrivate(), kp.getPublic(),
                    fixedClock().instant(), null);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A KeyStore exposing exactly one key. */
    public static KeyStore singleKeyStore(SigningKey key) {
        return new KeyStore() {
            @Override public SigningKey currentSigningKey() { return key; }
            @Override public List<VerificationKey> verificationKeys() { return List.of(key.toVerificationKey()); }
        };
    }

    private Fixtures() {
    }
}
