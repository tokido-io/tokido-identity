package io.tokido.identity.spring;

import io.tokido.identity.http.HttpRequest;
import io.tokido.identity.http.HttpResponse;
import io.tokido.identity.http.Router;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

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

    @GetMapping({"/authorize", "/token", "/userinfo"})
    public ResponseEntity<String> placeholder(jakarta.servlet.http.HttpServletRequest req) {
        // The route table knows context-relative paths; strip the servlet context path.
        String path = req.getRequestURI().substring(req.getContextPath().length());
        return toEntity(router.route(new HttpRequest("GET", path)));
    }

    private ResponseEntity<String> toEntity(HttpResponse r) {
        ResponseEntity.BodyBuilder b = ResponseEntity.status(r.status().code());
        r.headers().forEach(b::header);
        return b.body(r.body());
    }
}
