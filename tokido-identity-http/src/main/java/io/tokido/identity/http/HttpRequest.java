package io.tokido.identity.http;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A minimal, buffered, immutable request: method, normalized path, headers, and
 * (for {@code application/x-www-form-urlencoded} bodies) form parameters. Header
 * lookup via {@link #header(String)} is case-insensitive.
 *
 * @param method     HTTP method; non-null
 * @param path       request path with no trailing slash (except root "/"); non-null
 * @param headers    request headers; non-null, immutable
 * @param formParams parsed form-body parameters; non-null, immutable
 */
public record HttpRequest(String method, String path, Map<String, String> headers, Map<String, String> formParams) {

    public HttpRequest {
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(path, "path");
        if (path.length() > 1 && path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        headers = Map.copyOf(Objects.requireNonNull(headers, "headers"));
        formParams = Map.copyOf(Objects.requireNonNull(formParams, "formParams"));
    }

    /** A request with no headers or form parameters (e.g. a GET). */
    public HttpRequest(String method, String path) {
        this(method, path, Map.of(), Map.of());
    }

    /** Case-insensitive header lookup (HTTP header names are case-insensitive). */
    public Optional<String> header(String name) {
        Objects.requireNonNull(name, "name");
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) {
                return Optional.ofNullable(e.getValue());
            }
        }
        return Optional.empty();
    }

    /** A single form parameter value, or null if absent. */
    public String formParam(String name) {
        return formParams.get(Objects.requireNonNull(name, "name"));
    }
}
