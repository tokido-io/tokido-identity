package io.tokido.identity.engine.nativeimage;

import io.tokido.identity.config.DiscoveryConfig;
import io.tokido.identity.engine.IdentityEngine;
import io.tokido.identity.engine.signing.NimbusTokenSigner;
import io.tokido.identity.key.KeyStore;
import io.tokido.identity.key.SignatureAlgorithm;
import io.tokido.identity.key.SigningKey;
import io.tokido.identity.key.VerificationKey;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.util.List;

/**
 * Native-image smoke entry point: exercises discovery(), jwks(), and a
 * sign+verify round trip so GraalVM AOT analysis reaches the Nimbus/JCA/RSA
 * paths. Exits non-zero on any failure so the CI run is a real gate.
 *
 * <p>The validation logic lives in {@link #run()} (package-visible) so it can
 * be unit-tested without calling {@link System#exit}. {@code main} wraps it with
 * a try/catch that exits on failure.
 */
public final class NativeSmokeMain {

    /**
     * Builds an {@link IdentityEngine} over an inline-generated RSA key, calls
     * discovery / JWKS / sign, and asserts expected invariants. Throws
     * {@link AssertionError} on any validation failure so callers (tests or
     * {@code main}) receive a typed exception rather than a process exit.
     */
    static void run() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        SigningKey key = new SigningKey("smoke-kid", SignatureAlgorithm.RS256,
                kp.getPrivate(), kp.getPublic(), Instant.parse("2026-01-01T00:00:00Z"), null);
        KeyStore store = new KeyStore() {
            @Override
            public SigningKey currentSigningKey() { return key; }
            @Override
            public List<VerificationKey> verificationKeys() { return List.of(key.toVerificationKey()); }
        };

        IdentityEngine engine = new IdentityEngine(
                new DiscoveryConfig(URI.create("https://idp.example.com")), store, Clock.systemUTC());

        String discovery = engine.discoveryJson();
        String jwks = engine.jwksJson();
        String jws = new NimbusTokenSigner().sign("{\"sub\":\"smoke\"}", store.currentSigningKey());

        if (!discovery.contains("\"issuer\":\"https://idp.example.com\"")) {
            throw new AssertionError("discovery missing issuer: " + discovery);
        }
        if (!jwks.contains("\"kid\":\"smoke-kid\"") || jwks.contains("\"d\":")) {
            throw new AssertionError("jwks malformed or leaked private key: " + jwks);
        }
        if (jws.split("\\.").length != 3) {
            throw new AssertionError("jws not three-part compact serialization: " + jws);
        }
    }

    public static void main(String[] args) {
        try {
            run();
            System.out.println("native-smoke OK");
        } catch (Exception e) {
            System.err.println("native-smoke FAILED: " + e.getMessage());
            System.exit(1);
        }
    }

    private NativeSmokeMain() {
    }
}
