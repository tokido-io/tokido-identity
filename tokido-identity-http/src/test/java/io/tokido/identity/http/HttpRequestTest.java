package io.tokido.identity.http;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HttpRequestTest {

    @Test
    void convenience_constructor_has_empty_headers_and_form() {
        HttpRequest req = new HttpRequest("GET", "/jwks");
        assertThat(req.headers()).isEmpty();
        assertThat(req.formParams()).isEmpty();
    }

    @Test
    void normalizes_trailing_slash() {
        assertThat(new HttpRequest("GET", "/token/").path()).isEqualTo("/token");
        assertThat(new HttpRequest("GET", "/").path()).isEqualTo("/");
    }

    @Test
    void header_lookup_is_case_insensitive() {
        HttpRequest req = new HttpRequest("POST", "/token",
                Map.of("Authorization", "Basic abc"), Map.of());
        assertThat(req.header("authorization")).contains("Basic abc");
        assertThat(req.header("AUTHORIZATION")).contains("Basic abc");
        assertThat(req.header("X-Missing")).isEmpty();
    }

    @Test
    void form_param_returns_value_or_null() {
        HttpRequest req = new HttpRequest("POST", "/token", Map.of(),
                Map.of("grant_type", "client_credentials"));
        assertThat(req.formParam("grant_type")).isEqualTo("client_credentials");
        assertThat(req.formParam("scope")).isNull();
    }

    @Test
    void maps_are_immutable_copies() {
        HttpRequest req = new HttpRequest("POST", "/token", Map.of("A", "b"), Map.of("c", "d"));
        assertThatThrownBy(() -> req.headers().put("x", "y"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> req.formParams().put("x", "y"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void rejects_null_method_and_path() {
        assertThatNullPointerException().isThrownBy(() -> new HttpRequest(null, "/x"));
        assertThatNullPointerException().isThrownBy(() -> new HttpRequest("GET", null));
    }
}
