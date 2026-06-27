package io.tokido.identity.protocol;

import org.apiguardian.api.API;

import java.net.URI;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * OIDC discovery / OAuth 2.0 authorization-server metadata produced by the
 * engine. Required fields are typed; {@link #toOrderedMap()} renders the wire
 * form, emitting explicit negative-capability flags and omitting empty optional
 * arrays (so v0.1 never advertises a capability it does not yet implement).
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.1.0")
public record DiscoveryDocument(
        URI issuer,
        URI authorizationEndpoint,
        URI tokenEndpoint,
        URI userinfoEndpoint,
        URI jwksUri,
        List<String> responseTypesSupported,
        List<String> responseModesSupported,
        List<String> subjectTypesSupported,
        List<String> idTokenSigningAlgValuesSupported,
        List<String> scopesSupported,
        List<String> claimsSupported,
        List<String> grantTypesSupported,
        List<String> codeChallengeMethodsSupported,
        List<String> tokenEndpointAuthMethodsSupported) {

    public DiscoveryDocument {
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(authorizationEndpoint, "authorizationEndpoint");
        Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
        Objects.requireNonNull(userinfoEndpoint, "userinfoEndpoint");
        Objects.requireNonNull(jwksUri, "jwksUri");
        responseTypesSupported = List.copyOf(responseTypesSupported);
        responseModesSupported = List.copyOf(responseModesSupported);
        subjectTypesSupported = List.copyOf(subjectTypesSupported);
        idTokenSigningAlgValuesSupported = List.copyOf(idTokenSigningAlgValuesSupported);
        scopesSupported = List.copyOf(scopesSupported);
        claimsSupported = List.copyOf(claimsSupported);
        grantTypesSupported = List.copyOf(grantTypesSupported);
        codeChallengeMethodsSupported = List.copyOf(codeChallengeMethodsSupported);
        tokenEndpointAuthMethodsSupported = List.copyOf(tokenEndpointAuthMethodsSupported);
    }

    /** Render the wire form: stable order, negative flags emitted, empty optional arrays omitted. */
    public Map<String, Object> toOrderedMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("issuer", issuer.toString());
        m.put("authorization_endpoint", authorizationEndpoint.toString());
        m.put("token_endpoint", tokenEndpoint.toString());
        m.put("userinfo_endpoint", userinfoEndpoint.toString());
        m.put("jwks_uri", jwksUri.toString());
        m.put("response_types_supported", responseTypesSupported);
        m.put("response_modes_supported", responseModesSupported);
        m.put("subject_types_supported", subjectTypesSupported);
        m.put("id_token_signing_alg_values_supported", idTokenSigningAlgValuesSupported);
        m.put("scopes_supported", scopesSupported);
        m.put("claims_supported", claimsSupported);
        putIfNotEmpty(m, "grant_types_supported", grantTypesSupported);
        putIfNotEmpty(m, "code_challenge_methods_supported", codeChallengeMethodsSupported);
        putIfNotEmpty(m, "token_endpoint_auth_methods_supported", tokenEndpointAuthMethodsSupported);
        m.put("request_uri_parameter_supported", false);
        m.put("request_parameter_supported", false);
        m.put("claims_parameter_supported", false);
        return m;
    }

    private static void putIfNotEmpty(Map<String, Object> m, String key, List<String> value) {
        if (!value.isEmpty()) {
            m.put(key, value);
        }
    }
}
