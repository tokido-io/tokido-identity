package io.tokido.identity.spring;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "tokido.identity.issuer=https://idp.example.com",
        "tokido.identity.dev-keys=true"
})
@AutoConfigureMockMvc
class DiscoveryEndpointsTest {

    @Autowired MockMvc mvc;

    @Test
    void serves_discovery() throws Exception {
        mvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.issuer").value("https://idp.example.com"))
                .andExpect(jsonPath("$.jwks_uri").value("https://idp.example.com/jwks"))
                .andExpect(jsonPath("$.id_token_signing_alg_values_supported[0]").value("RS256"))
                .andExpect(jsonPath("$.request_uri_parameter_supported").value(false));
    }

    @Test
    void serves_jwks() throws Exception {
        mvc.perform(get("/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].d").doesNotExist());
    }

    @Test
    void unbuilt_endpoint_is_501() throws Exception {
        mvc.perform(get("/authorize")).andExpect(status().isNotImplemented());
    }

    @Test
    void unbuilt_endpoints_are_501_for_any_method() throws Exception {
        // /authorize and /userinfo remain unbuilt: 501 for every method.
        mvc.perform(post("/authorize")).andExpect(status().isNotImplemented());
        mvc.perform(post("/userinfo")).andExpect(status().isNotImplemented());
    }

    @Test
    void get_token_is_405_with_allow_post() throws Exception {
        // /token is a real POST route now; GET must say "wrong method", not "not built".
        mvc.perform(get("/token"))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(header().string("Allow", "POST"));
    }

    @Test
    void wrong_method_on_jwks_is_405() throws Exception {
        mvc.perform(post("/jwks")).andExpect(status().isMethodNotAllowed());
    }
}
