package io.tokido.identity.engine;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import io.tokido.identity.config.DiscoveryConfig;
import io.tokido.identity.engine.signing.NimbusTokenSigner;
import io.tokido.identity.key.KeyStore;
import io.tokido.identity.key.SignatureAlgorithm;
import io.tokido.identity.key.SigningKey;
import io.tokido.identity.key.VerificationKey;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MultiInstanceSigningTest {

    @Test
    void token_signed_by_instance_a_verifies_via_instance_b_jwks() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        SigningKey shared = new SigningKey("shared-kid", SignatureAlgorithm.RS256,
                kp.getPrivate(), kp.getPublic(), Instant.parse("2026-01-01T00:00:00Z"), null);
        KeyStore store = new KeyStore() {
            @Override public SigningKey currentSigningKey() { return shared; }
            @Override public List<VerificationKey> verificationKeys() { return List.of(shared.toVerificationKey()); }
        };
        Clock clock = Clock.fixed(Instant.parse("2026-06-26T00:00:00Z"), ZoneOffset.UTC);

        IdentityEngine a = new IdentityEngine(new DiscoveryConfig(URI.create("https://idp.example.com")), store, clock);
        IdentityEngine b = new IdentityEngine(new DiscoveryConfig(URI.create("https://idp.example.com")), store, clock);

        // identical JWKS across instances
        assertThat(a.jwksJson()).isEqualTo(b.jwksJson());

        // sign on A, verify with B's published key
        String jws = new NimbusTokenSigner().sign("{\"sub\":\"x\"}", a.currentForTest());
        SignedJWT parsed = SignedJWT.parse(jws);
        JWKSet bKeys = JWKSet.parse(b.jwksJson());
        RSAKey bKey = bKeys.getKeyByKeyId("shared-kid").toRSAKey();
        assertThat(parsed.verify(new RSASSAVerifier(bKey))).isTrue();
    }
}
