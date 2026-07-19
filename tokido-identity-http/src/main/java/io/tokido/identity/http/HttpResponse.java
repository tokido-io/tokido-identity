package io.tokido.identity.http;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * A buffered, immutable response: status, body, headers.
 *
 * @param status  status; non-null
 * @param body    body string; non-null
 * @param headers response headers; non-null, immutable
 */
public record HttpResponse(HttpStatus status, String body, Map<String, String> headers) {
    public HttpResponse {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(body, "body");
        headers = Map.copyOf(Objects.requireNonNull(headers, "headers"));
    }

    /** JSON response with Content-Type and Cache-Control set. */
    public static HttpResponse json(HttpStatus status, String body, String cacheControl) {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Content-Type", MediaType.APPLICATION_JSON);
        h.put("Cache-Control", cacheControl);
        return new HttpResponse(status, body, h);
    }
}
