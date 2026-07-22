package io.tokido.identity.spring;

import com.jayway.jsonpath.JsonPath;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The access-token-ttl and token-audience properties drive the minted token. */
@SpringBootTest(properties = {
        "tokido.identity.issuer=https://idp.example.com",
        "tokido.identity.dev-keys=true",
        "tokido.identity.access-token-ttl=PT15M",
        "tokido.identity.token-audience=https://api.example.com"
})
@AutoConfigureMockMvc
class TokenConfigTest {

    @TestConfiguration
    static class DemoClientConfig {
        @Bean
        ClientStore clientStore(SecretHasher hasher) {
            InMemoryClientStore store = new InMemoryClientStore(hasher);
            store.register("demo-client", "demo-secret", Set.of("client_credentials"),
                    Set.of("read"), Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
            return store;
        }
    }

    @Autowired MockMvc mvc;

    @Test
    void ttl_and_audience_properties_are_applied() throws Exception {
        String basic = "Basic " + Base64.getEncoder()
                .encodeToString("demo-client:demo-secret".getBytes(StandardCharsets.UTF_8));
        MvcResult result = mvc.perform(post("/token")
                        .header("Authorization", basic)
                        .param("grant_type", "client_credentials")
                        .param("scope", "read"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.expires_in").value(900)) // PT15M
                .andReturn();

        String token = JsonPath.read(result.getResponse().getContentAsString(), "$.access_token");
        assertThat(SignedJWT.parse(token).getJWTClaimsSet().getAudience())
                .containsExactly("https://api.example.com");
    }
}
