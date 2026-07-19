package io.tokido.identity.engine;

import io.tokido.identity.config.DiscoveryConfig;
import io.tokido.identity.key.KeyStore;
import io.tokido.identity.key.VerificationKey;
import io.tokido.identity.protocol.DiscoveryDocument;

import java.net.URI;
import java.util.List;

/** Builds the {@link DiscoveryDocument} from issuer config and the key store. */
public final class Discovery {

    private static final List<String> CLAIMS_BASELINE =
            List.of("sub", "iss", "aud", "exp", "iat");
    private static final List<String> SCOPES_BASELINE =
            List.of("openid", "profile", "email");

    private Discovery() {
    }

    public static DiscoveryDocument build(DiscoveryConfig config, KeyStore store) {
        URI issuer = config.issuer();
        List<String> algs = store.verificationKeys().stream()
                .map(VerificationKey::alg).map(Enum::name).distinct().toList();
        return new DiscoveryDocument(
                issuer,
                endpoint(issuer, "authorize"),
                endpoint(issuer, "token"),
                endpoint(issuer, "userinfo"),
                endpoint(issuer, "jwks"),
                List.of("code"),
                List.of("query"),
                List.of("public"),
                algs,
                SCOPES_BASELINE,
                CLAIMS_BASELINE,
                // Explicit values: RFC 8414 §2 gives omitted grant_types_supported the
                // default ["authorization_code", "implicit"] and omitted
                // token_endpoint_auth_methods_supported "client_secret_basic", so
                // omission would advertise MORE than v0.1 intends, not less.
                List.of("authorization_code"),
                List.of(),   // code_challenge_methods_supported — no spec default; arrives with PKCE in v0.3
                List.of("client_secret_basic"));
    }

    private static URI endpoint(URI issuer, String path) {
        String base = issuer.toString();
        String sep = base.endsWith("/") ? "" : "/";
        return URI.create(base + sep + path);
    }
}
