package io.tokido.identity.spring;

import io.tokido.identity.http.HttpRequest;
import io.tokido.identity.http.HttpResponse;
import io.tokido.identity.http.Router;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Binds the framework-neutral Router to Spring MVC. Thin shim, no logic. */
@RestController
public class DiscoveryController {

    private final Router router;

    public DiscoveryController(Router router) {
        this.router = router;
    }

    @GetMapping("/.well-known/openid-configuration")
    public ResponseEntity<String> discovery() {
        return toEntity(router.route(new HttpRequest("GET", "/.well-known/openid-configuration")));
    }

    @GetMapping("/jwks")
    public ResponseEntity<String> jwks() {
        return toEntity(router.route(new HttpRequest("GET", "/jwks")));
    }

    /**
     * Token endpoint. All methods route through the table (POST is handled; other
     * methods answer 405 Allow: POST), so Spring and non-Spring adapters agree. The
     * {@code Authorization} header and parsed form parameters are forwarded to the engine.
     */
    @RequestMapping("/token")
    public ResponseEntity<String> token(jakarta.servlet.http.HttpServletRequest req) {
        Map<String, String> headers = new LinkedHashMap<>();
        String auth = req.getHeader("Authorization");
        if (auth != null) {
            headers.put("Authorization", auth);
        }
        // Read parameters from the request body only. The servlet parameter map merges
        // the query string with the body, but credentials in a URL are an RFC 6749 §2.3.1
        // anti-pattern (they leak into logs/proxies/history), so query params are excluded.
        Set<String> queryNames = queryParamNames(req.getQueryString());
        Map<String, String> form = new LinkedHashMap<>();
        req.getParameterMap().forEach((k, v) -> {
            if (!queryNames.contains(k) && v != null && v.length > 0) {
                form.put(k, v[0]);
            }
        });
        return toEntity(router.route(new HttpRequest(req.getMethod(), "/token", headers, form)));
    }

    private static Set<String> queryParamNames(String queryString) {
        Set<String> names = new HashSet<>();
        if (queryString != null && !queryString.isBlank()) {
            for (String pair : queryString.split("&")) {
                if (pair.isEmpty()) {
                    continue;
                }
                int eq = pair.indexOf('=');
                String name = eq >= 0 ? pair.substring(0, eq) : pair;
                names.add(URLDecoder.decode(name, StandardCharsets.UTF_8));
            }
        }
        return names;
    }

    @RequestMapping({"/authorize", "/userinfo"})
    public ResponseEntity<String> placeholder(jakarta.servlet.http.HttpServletRequest req) {
        // Unbuilt endpoints answer 501 for every method. The route table knows
        // context-relative paths; strip the servlet context path.
        String path = req.getRequestURI().substring(req.getContextPath().length());
        return toEntity(router.route(new HttpRequest(req.getMethod(), path)));
    }

    private ResponseEntity<String> toEntity(HttpResponse r) {
        ResponseEntity.BodyBuilder b = ResponseEntity.status(r.status().code());
        r.headers().forEach(b::header);
        return b.body(r.body());
    }
}
