package io.tokido.identity.spring;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import io.tokido.identity.client.ClientAuthenticationMethod;
import io.tokido.identity.client.ClientStore;
import io.tokido.identity.client.SecretHasher;
import io.tokido.identity.dev.InMemoryClientStore;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "tokido.identity.issuer=https://idp.example.com",
        "tokido.identity.dev-keys=true"
})
@AutoConfigureMockMvc
class TokenEndpointE2ETest {

    @TestConfiguration
    static class DemoClientConfig {
        @Bean
        ClientStore clientStore(SecretHasher hasher) {
            InMemoryClientStore store = new InMemoryClientStore(hasher);
            store.register("demo-client", "demo-secret", Set.of("client_credentials"),
                    Set.of("read", "write"),
                    Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                            ClientAuthenticationMethod.CLIENT_SECRET_POST));
            return store;
        }
    }

    @Autowired
    MockMvc mvc;

    private static String basic(String id, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void issues_token_verifiable_against_jwks() throws Exception {
        MvcResult result = mvc.perform(post("/token")
                        .header("Authorization", basic("demo-client", "demo-secret"))
                        .param("grant_type", "client_credentials")
                        .param("scope", "read"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(header().string("Pragma", "no-cache"))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(3600))
                .andExpect(jsonPath("$.scope").value("read"))
                .andReturn();

        String accessToken = JsonPath.read(result.getResponse().getContentAsString(), "$.access_token");
        SignedJWT jwt = SignedJWT.parse(accessToken);

        // The token must verify against the published JWKS with its kid.
        String jwksJson = mvc.perform(get("/jwks")).andReturn().getResponse().getContentAsString();
        RSAKey jwk = (RSAKey) JWKSet.parse(jwksJson).getKeyByKeyId(jwt.getHeader().getKeyID());
        assertThat(jwt.verify(new RSASSAVerifier(jwk.toRSAPublicKey()))).isTrue();

        assertThat(jwt.getJWTClaimsSet().getStringClaim("client_id")).isEqualTo("demo-client");
        assertThat(jwt.getJWTClaimsSet().getStringClaim("scope")).isEqualTo("read");
        assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo("https://idp.example.com");
        assertThat(jwt.getJWTClaimsSet().getJWTID()).isNotBlank();
    }

    @Test
    void issues_token_via_client_secret_post() throws Exception {
        mvc.perform(post("/token")
                        .param("grant_type", "client_credentials")
                        .param("client_id", "demo-client")
                        .param("client_secret", "demo-secret")
                        .param("scope", "read write"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scope").value("read write"));
    }

    @Test
    void credentials_in_query_string_are_ignored() throws Exception {
        // Credentials passed in the URL query must not authenticate (RFC 6749 §2.3.1):
        // only the Authorization header and form body are honoured.
        mvc.perform(post("/token")
                        .queryParam("client_id", "demo-client")
                        .queryParam("client_secret", "demo-secret")
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    void bad_secret_via_basic_is_401_with_challenge() throws Exception {
        mvc.perform(post("/token")
                        .header("Authorization", basic("demo-client", "WRONG"))
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Basic"))
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }
}
