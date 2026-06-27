package io.tokido.identity.http;

import io.tokido.identity.engine.IdentityEngine;

import java.util.Objects;
import java.util.Set;

/**
 * Transport-neutral route table mapping a path to an engine call. The single
 * place routes are defined, so every runtime adapter (Spring now, FaaS later)
 * stays a thin binding shim.
 */
public final class Router {

    private static final String DISCOVERY = "/.well-known/openid-configuration";
    private static final String JWKS = "/jwks";
    private static final Set<String> NOT_YET_IMPLEMENTED = Set.of("/authorize", "/token", "/userinfo");
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
            return HttpResponse.json(HttpStatus.OK, engine.discoveryJson(), CACHE);
        }
        if (JWKS.equals(path)) {
            return HttpResponse.json(HttpStatus.OK, engine.jwksJson(), CACHE);
        }
        if (NOT_YET_IMPLEMENTED.contains(path)) {
            return HttpResponse.json(HttpStatus.NOT_IMPLEMENTED, NOT_IMPLEMENTED_BODY, "no-store");
        }
        return HttpResponse.json(HttpStatus.NOT_FOUND,
                "{\"error\":\"not_found\"}", "no-store");
    }
}
