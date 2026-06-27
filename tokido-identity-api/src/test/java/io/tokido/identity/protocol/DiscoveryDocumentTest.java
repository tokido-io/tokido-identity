package io.tokido.identity.protocol;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DiscoveryDocumentTest {

    private static DiscoveryDocument sample() {
        return new DiscoveryDocument(
                URI.create("https://idp.example.com"),
                URI.create("https://idp.example.com/authorize"),
                URI.create("https://idp.example.com/token"),
                URI.create("https://idp.example.com/userinfo"),
                URI.create("https://idp.example.com/jwks"),
                List.of("code"),
                List.of("query"),
                List.of("public"),
                List.of("RS256"),
                List.of("openid", "profile", "email"),
                List.of("sub", "iss", "aud", "exp", "iat"),
                List.of(),   // grantTypesSupported (omitted in v0.1)
                List.of(),   // codeChallengeMethodsSupported (omitted in v0.1)
                List.of());  // tokenEndpointAuthMethodsSupported (omitted in v0.1)
    }

    @Test
    void ordered_map_has_required_fields() {
        Map<String, Object> m = sample().toOrderedMap();
        assertThat(m).containsEntry("issuer", "https://idp.example.com");
        assertThat(m).containsEntry("jwks_uri", "https://idp.example.com/jwks");
        assertThat(m.get("scopes_supported")).asInstanceOf(
                org.assertj.core.api.InstanceOfAssertFactories.list(String.class)).contains("openid");
        assertThat(m).containsEntry("id_token_signing_alg_values_supported", List.of("RS256"));
        assertThat(m).containsEntry("response_modes_supported", List.of("query"));
    }

    @Test
    void emits_negative_capability_flags() {
        Map<String, Object> m = sample().toOrderedMap();
        assertThat(m).containsEntry("request_uri_parameter_supported", false);
        assertThat(m).containsEntry("request_parameter_supported", false);
        assertThat(m).containsEntry("claims_parameter_supported", false);
    }

    @Test
    void omits_empty_optional_arrays() {
        Map<String, Object> m = sample().toOrderedMap();
        assertThat(m).doesNotContainKey("grant_types_supported");
        assertThat(m).doesNotContainKey("code_challenge_methods_supported");
        assertThat(m).doesNotContainKey("token_endpoint_auth_methods_supported");
    }

    @Test
    void includes_optional_arrays_when_present() {
        DiscoveryDocument d = new DiscoveryDocument(
                URI.create("https://i"), URI.create("https://i/a"), URI.create("https://i/t"),
                URI.create("https://i/u"), URI.create("https://i/j"),
                List.of("code"), List.of("query"), List.of("public"), List.of("RS256"),
                List.of("openid"), List.of("sub"),
                List.of("authorization_code"), List.of("S256"), List.of("client_secret_basic"));
        Map<String, Object> m = d.toOrderedMap();
        assertThat(m).containsEntry("grant_types_supported", List.of("authorization_code"));
        assertThat(m).containsEntry("code_challenge_methods_supported", List.of("S256"));
        assertThat(m).containsEntry("token_endpoint_auth_methods_supported", List.of("client_secret_basic"));
    }
}
