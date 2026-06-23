package io.tokido.auth.resource;

import io.tokido.auth.model.AuthSession;
import io.tokido.auth.repository.AuthSessionRepository;
import io.tokido.auth.service.AuthClientService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import java.time.Instant;
import java.util.UUID;

@ApplicationScoped
@Path("/oauth/authorize")
public class AuthorizeResource {
    private final AuthClientService clientService;
    private final AuthSessionRepository sessionRepo;
    private final String uiOrigin;

    @Inject
    public AuthorizeResource(AuthClientService clientService,
                              AuthSessionRepository sessionRepo,
                              @ConfigProperty(name = "hosted.ui.origin") String uiOrigin) {
        this.clientService = clientService;
        this.sessionRepo = sessionRepo;
        this.uiOrigin = uiOrigin;
    }

    @GET
    public Response authorize(
        @QueryParam("client_id")             String clientId,
        @QueryParam("redirect_uri")          String redirectUri,
        @QueryParam("response_type")         String responseType,
        @QueryParam("scope")                 String scope,
        @QueryParam("login_hint")            String loginHint,
        @QueryParam("code_challenge")        String codeChallenge,
        @QueryParam("code_challenge_method") String codeChallengeMethod,
        @QueryParam("state")                 String state
    ) {
        if (clientId == null || clientId.isBlank())
            return Response.status(400).entity("missing client_id").build();

        var client = clientService.getClient(clientId).orElse(null);
        if (client == null)
            return Response.status(400).entity("unknown client_id").build();

        // RFC 6749 §10.6: invalid redirect_uri must return 400, never redirect
        boolean validRedirect = clientService.isRedirectUriAllowed(client, redirectUri);
        if (!validRedirect)
            return Response.status(400).entity("invalid redirect_uri").build();

        if (!"code".equals(responseType))
            return redirectError(redirectUri, state, "unsupported_response_type",
                "Only code response_type is supported.");

        if (codeChallenge == null || codeChallenge.isBlank())
            return redirectError(redirectUri, state, "invalid_request", "code_challenge required.");
        if (!"S256".equals(codeChallengeMethod))
            return redirectError(redirectUri, state, "invalid_request", "code_challenge_method must be S256.");
        if (loginHint == null || loginHint.isBlank())
            return redirectError(redirectUri, state, "invalid_request", "login_hint required.");

        var session = new AuthSession();
        session.setSessionId(UUID.randomUUID().toString());
        session.setClientId(clientId);
        session.setLoginHint(loginHint);
        session.setRedirectUri(redirectUri);
        session.setCodeChallenge(codeChallenge);
        session.setCodeChallengeMethod(codeChallengeMethod);
        session.setState(state);
        session.setStatus("pending");
        session.setFailedAttempts(0);
        session.setCreatedAt(Instant.now().toString());
        session.setTtl(Instant.now().getEpochSecond() + 900);
        sessionRepo.save(session);

        return Response.status(302)
            .header("Location", uiOrigin + "/ui/?session_id=" + session.getSessionId())
            .build();
    }

    private Response redirectError(String redirectUri, String state,
                                    String error, String description) {
        if (redirectUri == null) return Response.status(400).build();
        String url = redirectUri + "?error=" + error +
            "&error_description=" + java.net.URLEncoder.encode(description, java.nio.charset.StandardCharsets.UTF_8) +
            (state != null ? "&state=" + java.net.URLEncoder.encode(state, java.nio.charset.StandardCharsets.UTF_8) : "");
        return Response.status(302).header("Location", url).build();
    }
}
