package io.tokido.auth.resource;

import io.tokido.auth.service.JwtService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import java.util.List;
import java.util.Map;
import static java.util.Map.entry;

@ApplicationScoped
@Path("/.well-known")
public class OidcResource {
    private final String origin;
    private final String issuer;
    private final JwtService jwtService;

    @Inject
    public OidcResource(@ConfigProperty(name = "hosted.ui.origin") String origin,
                        @ConfigProperty(name = "issuer") String issuer,
                        JwtService jwtService) {
        this.origin = origin;
        this.issuer = issuer;
        this.jwtService = jwtService;
    }

    @GET
    @Path("/openid-configuration")
    @Produces(MediaType.APPLICATION_JSON)
    public Response discovery() {
        return Response.ok(Map.ofEntries(
            entry("issuer",                                issuer),
            entry("authorization_endpoint",               origin + "/oauth/authorize"),
            entry("token_endpoint",                       origin + "/oauth/token"),
            entry("jwks_uri",                             origin + "/.well-known/jwks.json"),
            entry("scopes_supported",                     List.of("totp")),
            entry("response_types_supported",             List.of("code")),
            entry("grant_types_supported",                List.of("authorization_code")),
            entry("token_endpoint_auth_methods_supported",List.of("client_secret_post", "none")),
            entry("code_challenge_methods_supported",     List.of("S256")),
            entry("subject_types_supported",              List.of("public")),
            entry("id_token_signing_alg_values_supported",List.of("RS256"))
        )).build();
    }

    @GET
    @Path("/jwks.json")
    @Produces(MediaType.APPLICATION_JSON)
    public Response jwks() {
        return Response.ok(Map.of("keys", jwtService.publicJwks()))
            .header("Cache-Control", "public, max-age=3600")
            .build();
    }
}
