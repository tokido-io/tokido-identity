package io.tokido.identity.engine.nativeimage;

import io.tokido.identity.client.ClientAuthenticationMethod;
import io.tokido.identity.client.ClientStore;
import io.tokido.identity.client.RegisteredClient;
import io.tokido.identity.config.DiscoveryConfig;
import io.tokido.identity.engine.IdentityEngine;
import io.tokido.identity.engine.client.Pbkdf2SecretHasher;
import io.tokido.identity.engine.grant.TokenResult;
import io.tokido.identity.engine.signing.NimbusTokenSigner;
import io.tokido.identity.key.KeyStore;
import io.tokido.identity.key.SignatureAlgorithm;
import io.tokido.identity.key.SigningKey;
import io.tokido.identity.key.VerificationKey;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

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
     * discovery / JWKS / sign+verify, and asserts expected invariants. Throws
     * {@link IllegalStateException} on any validation failure so callers (tests or
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
            throw new IllegalStateException("discovery missing issuer: " + discovery);
        }
        if (!jwks.contains("\"kid\":\"smoke-kid\"") || jwks.contains("\"d\":")) {
            throw new IllegalStateException("jwks malformed or leaked private key: " + jwks);
        }
        if (jws.split("\\.").length != 3) {
            throw new IllegalStateException("jws not three-part compact serialization: " + jws);
        }

        // Verify the JWS signature using the public key to ensure verify paths are
        // exercised by GraalVM AOT analysis (distinct from signing paths)
        com.nimbusds.jwt.SignedJWT parsed = com.nimbusds.jwt.SignedJWT.parse(jws);
        boolean verified = parsed.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(
                (java.security.interfaces.RSAPublicKey) key.publicKey()));
        if (!verified) {
            throw new IllegalStateException("jws signature did not verify");
        }

        // Exercise PBKDF2 hashing so GraalVM AOT reaches the JCA SecretKeyFactory path.
        Pbkdf2SecretHasher hasher = new Pbkdf2SecretHasher(10_000);
        String stored = hasher.hash("smoke-secret");
        if (!hasher.matches("smoke-secret", stored) || hasher.matches("wrong", stored)) {
            throw new IllegalStateException("secret hashing round-trip failed");
        }

        // Exercise the full client_credentials token path: authenticate + mint + verify.
        RegisteredClient client = new RegisteredClient("smoke-client", stored,
                Set.of("client_credentials"), Set.of("api"),
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
        ClientStore clientStore =
                id -> "smoke-client".equals(id) ? Optional.of(client) : Optional.empty();
        IdentityEngine tokenEngine = IdentityEngine.builder()
                .discoveryConfig(new DiscoveryConfig(URI.create("https://idp.example.com")))
                .keyStore(store).clock(Clock.systemUTC())
                .tokenSigner(new NimbusTokenSigner()).clientStore(clientStore).secretHasher(hasher)
                .build();
        String basic = "Basic " + Base64.getEncoder()
                .encodeToString("smoke-client:smoke-secret".getBytes(StandardCharsets.UTF_8));
        TokenResult result = tokenEngine.token(basic, Map.of("grant_type", "client_credentials", "scope", "api"));
        if (!(result instanceof TokenResult.Success success)) {
            throw new IllegalStateException("client_credentials token was not issued: " + result);
        }
        com.nimbusds.jwt.SignedJWT token = com.nimbusds.jwt.SignedJWT.parse(success.response().accessToken());
        boolean tokenVerified = token.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(
                (java.security.interfaces.RSAPublicKey) key.publicKey()));
        var claims = token.getJWTClaimsSet();
        if (!tokenVerified
                || !"smoke-client".equals(claims.getStringClaim("client_id"))
                || !"api".equals(claims.getStringClaim("scope"))
                || claims.getJWTID() == null || claims.getJWTID().isBlank()
                || claims.getAudience().isEmpty()) {
            throw new IllegalStateException("client_credentials token claims invalid");
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
