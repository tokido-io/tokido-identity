package io.tokido.identity.conformance;

import com.nimbusds.jose.jwk.JWKSet;
import io.tokido.identity.example.IdpApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = IdpApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "tokido.identity.issuer=https://idp.example.com")
class DiscoveryConformanceTest {

    @LocalServerPort int port;
    private final RestTemplate http = new RestTemplateBuilder().build();

    @SuppressWarnings("unchecked")
    private Map<String, Object> discovery() {
        return http.getForObject(
                "http://localhost:" + port + "/.well-known/openid-configuration", Map.class);
    }

    @Test
    void discovery_has_required_fields() {
        Map<String, Object> d = discovery();
        assertThat(d).containsKeys("issuer", "authorization_endpoint", "token_endpoint",
                "jwks_uri", "response_types_supported", "subject_types_supported",
                "id_token_signing_alg_values_supported");
        // issuer is the configured https issuer, exact-match, no query/fragment
        assertThat(d.get("issuer")).isEqualTo("https://idp.example.com");
    }

    @Test
    void scopes_include_openid_and_alg_is_rs256_only() {
        Map<String, Object> d = discovery();
        assertThat((List<String>) d.get("scopes_supported")).contains("openid");
        assertThat((List<String>) d.get("id_token_signing_alg_values_supported"))
                .containsExactly("RS256");
        assertThat((List<String>) d.get("id_token_signing_alg_values_supported"))
                .doesNotContain("none");
    }

    @Test
    void emits_negative_capability_flags() {
        Map<String, Object> d = discovery();
        assertThat(d).containsEntry("request_uri_parameter_supported", false);
        assertThat(d).containsEntry("request_parameter_supported", false);
        assertThat(d).containsEntry("claims_parameter_supported", false);
    }

    @Test
    void advertises_explicit_grant_capabilities_without_implicit() {
        // Explicit values narrow the RFC 8414 omission defaults (which would
        // imply the implicit grant); code_challenge_methods_supported has no
        // default, so omission is accurate until PKCE lands in v0.3.
        Map<String, Object> d = discovery();
        assertThat(d).containsEntry("grant_types_supported", List.of("authorization_code"));
        assertThat(d).containsEntry("token_endpoint_auth_methods_supported", List.of("client_secret_basic"));
        assertThat((List<String>) d.get("grant_types_supported")).doesNotContain("implicit");
        assertThat(d).doesNotContainKey("code_challenge_methods_supported");
    }

    @Test
    void jwks_is_wellformed_and_public_only() throws Exception {
        String json = http.getForObject("http://localhost:" + port + "/jwks", String.class);
        // Must parse as a JWK Set and contain no private material.
        JWKSet set = JWKSet.parse(json);
        assertThat(set.getKeys()).isNotEmpty();
        assertThat(set.getKeys()).allSatisfy(k -> {
            assertThat(k.getKeyID()).isNotBlank();
            assertThat(k.getKeyType().getValue()).isEqualTo("RSA");
            assertThat(k.isPrivate()).isFalse();
        });
        assertThat(json).doesNotContain("\"d\":");
        // self-consistency: advertised alg matches the JWKS key alg coverage
        Map<String, Object> d = discovery();
        assertThat((List<String>) d.get("id_token_signing_alg_values_supported"))
                .containsExactly("RS256");
    }

    @Test
    void jwks_uri_matches_issuer_base() {
        Map<String, Object> d = discovery();
        assertThat((String) d.get("jwks_uri")).startsWith("https://idp.example.com");
    }
}
