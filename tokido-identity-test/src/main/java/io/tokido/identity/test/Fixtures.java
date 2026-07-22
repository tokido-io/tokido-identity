package io.tokido.identity.test;

import io.tokido.identity.client.ClientAuthenticationMethod;
import io.tokido.identity.client.RegisteredClient;
import io.tokido.identity.client.SecretHasher;
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
import java.util.Set;

/** Reusable test fixtures for framework and plugin authors. */
public final class Fixtures {

    /**
     * A trivial, deterministic {@link SecretHasher} for tests: {@code hash(s) == "stub:" + s}.
     * NOT secure — it keeps the test module free of any real hashing algorithm (which lives
     * in the engine). Never use outside tests.
     */
    public static SecretHasher stubSecretHasher() {
        return new SecretHasher() {
            @Override public String hash(String plaintextSecret) {
                return "stub:" + plaintextSecret;
            }

            @Override public boolean matches(String plaintextSecret, String storedHash) {
                return ("stub:" + plaintextSecret).equals(storedHash);
            }
        };
    }

    /** A demo confidential client permitting client_credentials with the given hasher. */
    public static RegisteredClient demoClient(SecretHasher hasher) {
        return new RegisteredClient("demo-client", hasher.hash("demo-secret"),
                Set.of("client_credentials"), Set.of("read", "write"),
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                        ClientAuthenticationMethod.CLIENT_SECRET_POST));
    }

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
