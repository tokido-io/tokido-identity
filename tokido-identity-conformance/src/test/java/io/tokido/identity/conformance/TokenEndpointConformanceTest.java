package io.tokido.identity.conformance;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import io.tokido.identity.example.IdpApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Behavioural conformance for the {@code client_credentials} token endpoint against
 * the running example IdP.
 *
 * <p><strong>Scope of this claim:</strong> {@code client_credentials} is a plain
 * OAuth 2.0 grant (RFC 6749 §4.4) and is <em>not</em> part of the OpenID Connect
 * Basic OP certification plan (which covers the interactive {@code authorization_code}
 * flow and arrives in v0.3). These tests assert RFC 6749 §5.1/§5.2 semantics and that
 * the token is a valid signed JWS verifiable against the published JWKS — they do not
 * claim OIDF certification coverage. The dockerised OIDF suite remains informational
 * ({@code continue-on-error}), as in v0.1.
 */
@SpringBootTest(classes = IdpApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "tokido.identity.issuer=https://idp.example.com")
class TokenEndpointConformanceTest {

    @LocalServerPort int port;
    private final RestTemplate http = new RestTemplateBuilder()
            .errorHandler(new NoOpErrorHandler()).build();

    private String url() {
        return "http://localhost:" + port + "/token";
    }

    private static HttpHeaders basicForm(String id, String secret) {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        if (id != null) {
            h.set("Authorization", "Basic " + Base64.getEncoder()
                    .encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8)));
        }
        return h;
    }

    private static MultiValueMap<String, String> form(String... kv) {
        MultiValueMap<String, String> f = new LinkedMultiValueMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            f.add(kv[i], kv[i + 1]);
        }
        return f;
    }

    @SuppressWarnings("unchecked")
    @Test
    void issues_token_that_verifies_against_jwks_with_expected_claims() throws Exception {
        ResponseEntity<Map> resp = http.postForEntity(url(),
                new HttpEntity<>(form("grant_type", "client_credentials", "scope", "read"),
                        basicForm("demo-client", "demo-secret")), Map.class);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resp.getHeaders().getCacheControl()).contains("no-store");
        Map<String, Object> body = resp.getBody();
        assertThat(body).containsEntry("token_type", "Bearer").containsEntry("scope", "read");

        SignedJWT jwt = SignedJWT.parse((String) body.get("access_token"));
        String jwks = http.getForObject("http://localhost:" + port + "/jwks", String.class);
        RSAKey jwk = (RSAKey) JWKSet.parse(jwks).getKeyByKeyId(jwt.getHeader().getKeyID());
        assertThat(jwt.verify(new RSASSAVerifier(jwk.toRSAPublicKey()))).isTrue();

        var claims = jwt.getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo("https://idp.example.com");
        assertThat(claims.getStringClaim("client_id")).isEqualTo("demo-client");
        assertThat(claims.getStringClaim("scope")).isEqualTo("read");
        assertThat(claims.getJWTID()).isNotBlank();
        assertThat(claims.getAudience()).isNotEmpty();
        assertThat(claims.getExpirationTime()).isAfter(claims.getIssueTime());
    }

    @Test
    void requesting_disallowed_scope_is_invalid_scope() {
        ResponseEntity<Map> resp = http.postForEntity(url(),
                new HttpEntity<>(form("grant_type", "client_credentials", "scope", "read admin"),
                        basicForm("demo-client", "demo-secret")), Map.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(resp.getBody()).containsEntry("error", "invalid_scope");
    }

    @Test
    void bad_secret_via_basic_is_401_with_challenge() {
        ResponseEntity<Map> resp = http.postForEntity(url(),
                new HttpEntity<>(form("grant_type", "client_credentials"),
                        basicForm("demo-client", "WRONG")), Map.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(resp.getHeaders().getFirst("WWW-Authenticate")).isEqualTo("Basic");
        assertThat(resp.getBody()).containsEntry("error", "invalid_client");
    }

    @Test
    void unsupported_grant_type_is_rejected() {
        ResponseEntity<Map> resp = http.postForEntity(url(),
                new HttpEntity<>(form("grant_type", "password"),
                        basicForm("demo-client", "demo-secret")), Map.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(resp.getBody()).containsEntry("error", "unsupported_grant_type");
    }

    /** Lets 4xx responses return normally so the body can be asserted. */
    private static final class NoOpErrorHandler
            implements org.springframework.web.client.ResponseErrorHandler {
        @Override public boolean hasError(org.springframework.http.client.ClientHttpResponse response) {
            return false;
        }

        @Override public void handleError(org.springframework.http.client.ClientHttpResponse response) {
        }
    }
}
