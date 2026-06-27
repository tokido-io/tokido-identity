package io.tokido.identity.engine;

import io.tokido.identity.config.DiscoveryConfig;
import io.tokido.identity.key.KeyStore;
import io.tokido.identity.key.SignatureAlgorithm;
import io.tokido.identity.key.SigningKey;
import io.tokido.identity.key.VerificationKey;
import io.tokido.identity.protocol.DiscoveryDocument;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DiscoveryTest {

    private static KeyStore singleKeyStore() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        SigningKey k = new SigningKey("kid-1", SignatureAlgorithm.RS256, kp.getPrivate(), kp.getPublic(),
                Instant.parse("2026-01-01T00:00:00Z"), null);
        return new KeyStore() {
            @Override public SigningKey currentSigningKey() { return k; }
            @Override public List<VerificationKey> verificationKeys() { return List.of(k.toVerificationKey()); }
        };
    }

    @Test
    void derives_endpoints_from_issuer() throws Exception {
        DiscoveryDocument d = Discovery.build(
                new DiscoveryConfig(URI.create("https://idp.example.com")), singleKeyStore());
        assertThat(d.issuer()).isEqualTo(URI.create("https://idp.example.com"));
        assertThat(d.authorizationEndpoint()).isEqualTo(URI.create("https://idp.example.com/authorize"));
        assertThat(d.tokenEndpoint()).isEqualTo(URI.create("https://idp.example.com/token"));
        assertThat(d.userinfoEndpoint()).isEqualTo(URI.create("https://idp.example.com/userinfo"));
        assertThat(d.jwksUri()).isEqualTo(URI.create("https://idp.example.com/jwks"));
    }

    @Test
    void derives_endpoints_with_path_bearing_issuer() throws Exception {
        DiscoveryDocument d = Discovery.build(
                new DiscoveryConfig(URI.create("https://example.com/auth")), singleKeyStore());
        assertThat(d.authorizationEndpoint()).isEqualTo(URI.create("https://example.com/auth/authorize"));
        assertThat(d.jwksUri()).isEqualTo(URI.create("https://example.com/auth/jwks"));
    }

    @Test
    void advertises_required_baseline_and_alg_from_keystore() throws Exception {
        DiscoveryDocument d = Discovery.build(
                new DiscoveryConfig(URI.create("https://idp.example.com")), singleKeyStore());
        assertThat(d.responseTypesSupported()).containsExactly("code");
        assertThat(d.responseModesSupported()).containsExactly("query");
        assertThat(d.subjectTypesSupported()).containsExactly("public");
        assertThat(d.idTokenSigningAlgValuesSupported()).containsExactly("RS256");
        assertThat(d.scopesSupported()).contains("openid");
    }

    @Test
    void omits_optional_capability_arrays_in_v01() throws Exception {
        DiscoveryDocument d = Discovery.build(
                new DiscoveryConfig(URI.create("https://idp.example.com")), singleKeyStore());
        assertThat(d.grantTypesSupported()).isEmpty();
        assertThat(d.codeChallengeMethodsSupported()).isEmpty();
        assertThat(d.tokenEndpointAuthMethodsSupported()).isEmpty();
        assertThat(d.toOrderedMap()).doesNotContainKeys(
                "grant_types_supported", "code_challenge_methods_supported", "token_endpoint_auth_methods_supported");
    }
}
