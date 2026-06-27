package io.tokido.identity.http;

import java.util.Objects;

/**
 * A minimal, buffered, immutable request: method + normalized path. Expanded in
 * later increments (headers, query, body); v0.1 routes discovery/jwks by path.
 *
 * @param method HTTP method; non-null
 * @param path   request path with no trailing slash (except root "/"); non-null
 */
public record HttpRequest(String method, String path) {
    public HttpRequest {
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(path, "path");
        if (path.length() > 1 && path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
    }
}
