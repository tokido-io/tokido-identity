package io.tokido.identity.http;

import io.tokido.identity.engine.IdentityEngine;
import io.tokido.identity.engine.Json;
import io.tokido.identity.engine.grant.TokenResult;
import io.tokido.identity.grant.OAuthError;
import io.tokido.identity.grant.TokenResponse;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;
import java.util.function.Supplier;

/**
 * Transport-neutral route table mapping a path to an engine call. The single
 * place routes are defined, so every runtime adapter (Spring now, FaaS later)
 * stays a thin binding shim.
 */
public final class Router {

    private static final String DISCOVERY = "/.well-known/openid-configuration";
    private static final String JWKS = "/jwks";
    private static final String TOKEN = "/token";
    // /token is a real POST route as of v0.2; /authorize and /userinfo are still unbuilt.
    private static final java.util.Set<String> NOT_YET_IMPLEMENTED = java.util.Set.of("/authorize", "/userinfo");
    private static final String CACHE = "public, max-age=300";
    private static final String NOT_IMPLEMENTED_BODY =
            "{\"error\":\"not_implemented\",\"error_description\":"
            + "\"endpoint planned; not implemented in this version\"}";

    private final IdentityEngine engine;

    public Router(IdentityEngine engine) {
        this.engine = Objects.requireNonNull(engine, "engine");
    }

    public HttpResponse route(HttpRequest req) {
        String path = req.path();
        if (DISCOVERY.equals(path)) {
            return getOnly(req, engine::discoveryJson);
        }
        if (JWKS.equals(path)) {
            return getOnly(req, engine::jwksJson);
        }
        if (TOKEN.equals(path)) {
            return token(req);
        }
        if (NOT_YET_IMPLEMENTED.contains(path)) {
            // Functionality is entirely unimplemented, so 501 for every method.
            return HttpResponse.json(HttpStatus.NOT_IMPLEMENTED, NOT_IMPLEMENTED_BODY, "no-store");
        }
        return HttpResponse.json(HttpStatus.NOT_FOUND,
                "{\"error\":\"not_found\"}", "no-store");
    }

    private HttpResponse token(HttpRequest req) {
        if (!"POST".equals(req.method())) {
            Map<String, String> headers = tokenHeaders();
            headers.put("Allow", "POST");
            return new HttpResponse(HttpStatus.METHOD_NOT_ALLOWED, "{\"error\":\"method_not_allowed\"}", headers);
        }
        TokenResult result = engine.token(req.header("Authorization").orElse(null), req.formParams());
        return switch (result) {
            case TokenResult.Success success -> success(success.response());
            case TokenResult.Error error -> error(error);
        };
    }

    private static HttpResponse success(TokenResponse response) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", response.accessToken());
        body.put("token_type", response.tokenType());
        body.put("expires_in", response.expiresIn().toSeconds());
        body.put("scope", String.join(" ", new TreeSet<>(response.scope())));
        return new HttpResponse(HttpStatus.OK, Json.write(body), tokenHeaders());
    }

    private static HttpResponse error(TokenResult.Error error) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error.error().code());
        if (error.description() != null && !error.description().isBlank()) {
            body.put("error_description", error.description());
        }
        Map<String, String> headers = tokenHeaders();
        HttpStatus status = statusFor(error);
        if (error.error() == OAuthError.INVALID_CLIENT && error.basicChallenge()) {
            headers.put("WWW-Authenticate", "Basic");
        }
        return new HttpResponse(status, Json.write(body), headers);
    }

    private static HttpStatus statusFor(TokenResult.Error error) {
        return switch (error.error()) {
            case INVALID_CLIENT -> error.basicChallenge() ? HttpStatus.UNAUTHORIZED : HttpStatus.BAD_REQUEST;
            case SERVER_ERROR -> HttpStatus.SERVER_ERROR;
            default -> HttpStatus.BAD_REQUEST;
        };
    }

    /** Token responses must never be cached (RFC 6749 §5.1). */
    private static Map<String, String> tokenHeaders() {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Content-Type", MediaType.APPLICATION_JSON);
        h.put("Cache-Control", "no-store");
        h.put("Pragma", "no-cache");
        return h;
    }

    private static HttpResponse getOnly(HttpRequest req, Supplier<String> body) {
        if ("GET".equals(req.method())) {
            return HttpResponse.json(HttpStatus.OK, body.get(), CACHE);
        }
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", MediaType.APPLICATION_JSON);
        headers.put("Cache-Control", "no-store");
        headers.put("Allow", "GET");
        return new HttpResponse(HttpStatus.METHOD_NOT_ALLOWED,
                "{\"error\":\"method_not_allowed\"}", headers);
    }
}
