package io.tokido.identity.spring;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "tokido.identity.issuer=https://idp.example.com",
        "tokido.identity.dev-keys=true"
})
@AutoConfigureMockMvc
class ContextPathTest {

    @Autowired MockMvc mvc;

    @Test
    void placeholder_endpoints_resolve_behind_servlet_context_path() throws Exception {
        // Deployed under a context path, the servlet request URI is "/idp/authorize"
        // but the route table knows "/authorize" — the shim must strip the context path.
        mvc.perform(get("/idp/authorize").contextPath("/idp"))
                .andExpect(status().isNotImplemented());
        mvc.perform(get("/idp/token").contextPath("/idp"))
                .andExpect(status().isNotImplemented());
    }
}
