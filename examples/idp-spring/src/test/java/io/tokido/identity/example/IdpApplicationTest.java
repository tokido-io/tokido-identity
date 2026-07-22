package io.tokido.identity.example;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@SpringBootTest
@AutoConfigureMockMvc
class IdpApplicationTest {

    @Autowired MockMvc mvc;

    @Test
    void discovery_and_jwks_have_stable_kid() throws Exception {
        String kid = com.jayway.jsonpath.JsonPath.read(
                mvc.perform(get("/jwks")).andReturn().getResponse().getContentAsString(),
                "$.keys[0].kid");
        // kid is pinned via the committed PEM, so it is stable and well-known.
        mvc.perform(get("/.well-known/openid-configuration")).andExpect(status().isOk());
        org.assertj.core.api.Assertions.assertThat(kid).isEqualTo("example-dev-key");
    }

    @Test
    void demo_client_receives_a_signed_scoped_token() throws Exception {
        String basic = "Basic " + Base64.getEncoder()
                .encodeToString("demo-client:demo-secret".getBytes(StandardCharsets.UTF_8));
        mvc.perform(post("/token")
                        .header("Authorization", basic)
                        .param("grant_type", "client_credentials")
                        .param("scope", "read"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.scope").value("read"))
                .andExpect(jsonPath("$.access_token").isNotEmpty());
    }
}
