package io.tokido.identity.config;

import org.apiguardian.api.API;

import java.net.URI;
import java.util.Objects;

/**
 * Engine-facing discovery configuration. The issuer is the base URL from which
 * all advertised endpoint URLs are derived. Must be https, or http for loopback
 * (localhost / 127.0.0.1) to support local development; no query or fragment.
 *
 * <p><strong>v0.1 limitation:</strong> the Spring adapter serves the endpoints at
 * the host root (e.g. {@code /.well-known/openid-configuration}, {@code /jwks}).
 * If the issuer carries a path (e.g. {@code https://host/auth}), discovery will
 * advertise endpoint URLs under that path which the v0.1 adapter does not serve.
 * Use a host-root issuer in v0.1; path-bearing issuers are a later increment.
 *
 * @param issuer issuer base URL; non-null
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.1.0")
public record DiscoveryConfig(URI issuer) {
    public DiscoveryConfig {
        Objects.requireNonNull(issuer, "issuer");
        String scheme = issuer.getScheme();
        String host = issuer.getHost();
        boolean loopback = host != null
                && (host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]"));
        if (!"https".equals(scheme) && !("http".equals(scheme) && loopback)) {
            throw new IllegalArgumentException("issuer must use https (http allowed only for loopback): " + issuer);
        }
        if (issuer.getQuery() != null || issuer.getFragment() != null) {
            throw new IllegalArgumentException("issuer must not contain query or fragment: " + issuer);
        }
    }
}
