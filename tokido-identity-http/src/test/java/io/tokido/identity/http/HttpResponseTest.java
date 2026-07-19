package io.tokido.identity.http;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HttpResponseTest {

    @Test
    void json_factory_sets_content_type_and_cache_control() {
        HttpResponse r = HttpResponse.json(HttpStatus.OK, "{}", "public, max-age=300");
        assertThat(r.status()).isEqualTo(HttpStatus.OK);
        assertThat(r.status().code()).isEqualTo(200);
        assertThat(r.body()).isEqualTo("{}");
        assertThat(r.headers()).containsEntry("Content-Type", "application/json")
                .containsEntry("Cache-Control", "public, max-age=300");
    }

    @Test
    void headers_are_immutable() {
        HttpResponse r = HttpResponse.json(HttpStatus.OK, "{}", "no-store");
        assertThatThrownBy(() -> r.headers().put("x", "y"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void http_status_ok_code() {
        assertThat(HttpStatus.OK.code()).isEqualTo(200);
    }

    @Test
    void http_status_not_found_code() {
        assertThat(HttpStatus.NOT_FOUND.code()).isEqualTo(404);
    }

    @Test
    void http_status_not_implemented_code() {
        assertThat(HttpStatus.NOT_IMPLEMENTED.code()).isEqualTo(501);
    }

    @Test
    void media_type_application_json() {
        assertThat(MediaType.APPLICATION_JSON).isEqualTo("application/json");
    }

    @Test
    void http_request_stores_method_and_path() {
        HttpRequest req = new HttpRequest("GET", "/test");
        assertThat(req.method()).isEqualTo("GET");
        assertThat(req.path()).isEqualTo("/test");
    }

    @Test
    void http_request_strips_trailing_slash() {
        HttpRequest req = new HttpRequest("GET", "/test/");
        assertThat(req.path()).isEqualTo("/test");
    }

    @Test
    void http_request_preserves_root_path() {
        HttpRequest req = new HttpRequest("GET", "/");
        assertThat(req.path()).isEqualTo("/");
    }

    @Test
    void http_request_requires_non_null_method() {
        assertThatThrownBy(() -> new HttpRequest(null, "/test"))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("method");
    }

    @Test
    void http_request_requires_non_null_path() {
        assertThatThrownBy(() -> new HttpRequest("GET", null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("path");
    }

    @Test
    void http_response_constructor_requires_non_null_status() {
        assertThatThrownBy(() -> new HttpResponse(null, "{}", java.util.Map.of()))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("status");
    }

    @Test
    void http_response_constructor_requires_non_null_body() {
        assertThatThrownBy(() -> new HttpResponse(HttpStatus.OK, null, java.util.Map.of()))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("body");
    }

    @Test
    void http_response_constructor_requires_non_null_headers() {
        assertThatThrownBy(() -> new HttpResponse(HttpStatus.OK, "{}", null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("headers");
    }
}
