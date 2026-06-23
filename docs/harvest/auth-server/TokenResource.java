package io.tokido.auth.resource;

import io.tokido.auth.repository.AuthCodeRepository;
import io.tokido.auth.repository.AuthSessionRepository;
import io.tokido.auth.service.AuthClientService;
import io.tokido.auth.service.JwtService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import software.amazon.awssdk.enhanced.dynamodb.*;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Collectors;

@ApplicationScoped
@Path("/oauth/token")
@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
public class TokenResource {

    // Minimal bean for reading created_at from totp-records
    @DynamoDbBean
    public static class TotpRecordMeta {
        private String appId, userId;
        private Long createdAt;

        @DynamoDbPartitionKey @DynamoDbAttribute("app_id")
        public String getAppId() { return appId; }
        public void setAppId(String v) { this.appId = v; }

        @DynamoDbSortKey @DynamoDbAttribute("user_id")
        public String getUserId() { return userId; }
        public void setUserId(String v) { this.userId = v; }

        @DynamoDbAttribute("created_at")
        public Long getCreatedAt() { return createdAt; }
        public void setCreatedAt(Long v) { this.createdAt = v; }
    }

    private static final TableSchema<TotpRecordMeta> TOTP_META_SCHEMA =
        TableSchema.fromBean(TotpRecordMeta.class);

    private final AuthCodeRepository codeRepo;
    private final AuthSessionRepository sessionRepo;
    private final AuthClientService clientService;
    private final DynamoDbEnhancedClient dynamoDb;
    private final String totpTableName;
    private final JwtService jwtService;
    private final Set<String> allowedOrigins;

    @Inject
    public TokenResource(AuthCodeRepository codeRepo,
                          AuthSessionRepository sessionRepo,
                          AuthClientService clientService,
                          DynamoDbEnhancedClient dynamoDb,
                          @ConfigProperty(name = "totp.records.table") String totpTableName,
                          JwtService jwtService,
                          @ConfigProperty(name = "auth.allowed.origins") String allowedOrigins) {
        this.codeRepo = codeRepo;
        this.sessionRepo = sessionRepo;
        this.clientService = clientService;
        this.dynamoDb = dynamoDb;
        this.totpTableName = totpTableName;
        this.jwtService = jwtService;
        this.allowedOrigins = Arrays.stream(allowedOrigins.split(","))
            .map(String::trim)
            .filter(origin -> !origin.isBlank())
            .collect(Collectors.toUnmodifiableSet());
    }

    @POST
    public Response token(
        @FormParam("grant_type")    String grantType,
        @FormParam("code")          String code,
        @FormParam("code_verifier") String codeVerifier,
        @FormParam("client_id")     String clientId,
        @FormParam("client_secret") String clientSecret,
        @FormParam("redirect_uri")  String redirectUri,
        @HeaderParam("Origin")      String origin
    ) {
        try {
            return tokenInternal(grantType, code, codeVerifier, clientId, clientSecret, redirectUri, origin);
        } catch (Exception e) {
            return error(500, "server_error", "An internal error occurred.", origin);
        }
    }

    private Response tokenInternal(
        String grantType,
        String code,
        String codeVerifier,
        String clientId,
        String clientSecret,
        String redirectUri,
        String origin
    ) {
        // 0. Validate grant_type (RFC 6749 §5.2)
        if (!"authorization_code".equals(grantType))
            return error(400, "unsupported_grant_type", "Only authorization_code grant type is supported.", origin);

        // Null guard on required parameters
        if (code == null || code.isBlank())
            return error(400, "invalid_grant", "Missing code parameter.", origin);
        if (redirectUri == null || redirectUri.isBlank())
            return error(400, "invalid_grant", "Missing redirect_uri parameter.", origin);

        // 1. Look up auth code
        var authCode = codeRepo.findById(code).orElse(null);
        if (authCode == null)
            return error(400, "invalid_grant", "Authorization code not found or expired.", origin);

        // 2. Validate client (before consuming the code, so client can retry with correct creds)
        if (clientId == null || clientId.isBlank())
            return error(400, "invalid_client", "Missing client_id.", origin);
        var client = clientService.getClient(clientId).orElse(null);
        if (client == null)
            return error(400, "invalid_client", "Unknown client_id.", origin);

        if (!client.publicClient() && (clientSecret == null || clientSecret.isBlank()))
            return error(400, "invalid_client", "Missing client_secret.", origin);

        if (!clientService.isClientSecretValid(client, clientSecret))
            return error(400, "invalid_client", "Invalid client credentials.", origin);

        // 3. Verify the auth code was issued to this client
        if (!clientId.equals(authCode.getClientId()))
            return error(400, "invalid_grant", "Authorization code was not issued to this client.", origin);

        // 4. Atomic mark-used — rejects replays (only after all validation passes)
        if (!codeRepo.markUsed(code))
            return error(400, "invalid_grant", "Authorization code has already been used.", origin);

        // 5. Validate session
        var session = sessionRepo.findById(authCode.getSessionId()).orElse(null);
        if (session == null)
            return error(400, "invalid_grant", "Session not found.", origin);

        if (!redirectUri.equals(session.getRedirectUri()))
            return error(400, "invalid_grant", "redirect_uri mismatch.", origin);

        // 6. PKCE: BASE64URL(SHA-256(codeVerifier)) must equal stored code_challenge
        String computed = computeChallenge(codeVerifier);
        if (!computed.equals(session.getCodeChallenge()))
            return error(400, "invalid_grant", "PKCE code_verifier verification failed.", origin);

        // 7. Read created_at (totp_enrolled_at) from totp-records
        long enrolledAt = readTotpEnrolledAt(client.appId(), authCode.getLoginHint());

        // 8. Mint tokens
        String idToken     = jwtService.signIdToken(authCode.getLoginHint(), clientId, enrolledAt);
        String accessToken = jwtService.signAccessToken(authCode.getLoginHint(), clientId);

        return cors(Response.ok(Map.of(
            "access_token", accessToken,
            "id_token",     idToken,
            "token_type",   "Bearer",
            "expires_in",   3600
        )).header("Cache-Control", "no-store"), origin).build();
    }

    @OPTIONS
    public Response options(@HeaderParam("Origin") String origin) {
        return cors(Response.ok(), origin).build();
    }

    private String computeChallenge(String verifier) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private long readTotpEnrolledAt(String appId, String loginHint) {
        var key = new TotpRecordMeta();
        key.setAppId(appId);
        key.setUserId(loginHint);
        var record = dynamoDb.table(totpTableName, TOTP_META_SCHEMA).getItem(key);
        return (record != null && record.getCreatedAt() != null) ? record.getCreatedAt() : 0L;
    }

    private Response error(int status, String code, String desc, String origin) {
        return cors(Response.status(status)
            .entity(Map.of("error", code, "error_description", desc)), origin)
            .build();
    }

    private Response.ResponseBuilder cors(Response.ResponseBuilder builder, String origin) {
        builder.header("Access-Control-Allow-Methods", "POST, OPTIONS");
        builder.header("Access-Control-Allow-Headers", "Content-Type");
        builder.header("Vary", "Origin");
        if (origin != null && allowedOrigins.contains(origin)) {
            builder.header("Access-Control-Allow-Origin", origin);
        }
        return builder;
    }
}
