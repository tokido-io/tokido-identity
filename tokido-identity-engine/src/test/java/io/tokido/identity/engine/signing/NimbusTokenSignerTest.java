package io.tokido.identity.engine.signing;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import io.tokido.identity.key.SignatureAlgorithm;
import io.tokido.identity.key.SigningKey;
import io.tokido.identity.signing.SigningException;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NimbusTokenSignerTest {

    private static SigningKey rsaKey(String kid) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        return new SigningKey(kid, SignatureAlgorithm.RS256, kp.getPrivate(), kp.getPublic(),
                Instant.parse("2026-01-01T00:00:00Z"), null);
    }

    @Test
    void signs_and_verifies_with_kid_header() throws Exception {
        SigningKey key = rsaKey("kid-1");
        NimbusTokenSigner signer = new NimbusTokenSigner();

        String jws = signer.sign("{\"sub\":\"alice\",\"iss\":\"https://idp\"}", key);

        SignedJWT parsed = SignedJWT.parse(jws);
        assertThat(parsed.getHeader().getKeyID()).isEqualTo("kid-1");
        assertThat(parsed.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) key.publicKey());
        assertThat(parsed.verify(verifier)).isTrue();
        assertThat(parsed.getJWTClaimsSet().getSubject()).isEqualTo("alice");
    }

    @Test
    void wraps_invalid_json_in_signing_exception() throws Exception {
        SigningKey key = rsaKey("kid-1");
        NimbusTokenSigner signer = new NimbusTokenSigner();
        assertThatThrownBy(() -> signer.sign("not-json", key))
                .isInstanceOf(SigningException.class);
    }
}
