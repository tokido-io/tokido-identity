package io.tokido.auth.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.*;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;
import java.util.Base64;

@ApplicationScoped
public class JwtService {
    @Inject SecretsManagerClient secretsManager;
    @ConfigProperty(name = "signing.key.secret.arn") String secretArn;
    @ConfigProperty(name = "issuer") String issuer;

    private RSAKey activeKey;

    // Test constructor — inject a pre-built key without needing Secrets Manager
    JwtService(RSAKey key, String issuer) {
        this.activeKey = key;
        this.issuer = issuer;
    }

    public JwtService() {}

    @PostConstruct
    void loadKey() throws Exception {
        if (activeKey != null) return; // set by test constructor
        var secret = secretsManager.getSecretValue(
            GetSecretValueRequest.builder().secretId(secretArn).build()
        ).secretString();
        // JSON format: { "keys": [{ "kid": "...", "status": "active", "private_key_pem": "...", "public_key_pem": "..." }] }
        var mapper = new ObjectMapper();
        var node = mapper.readTree(secret);
        var kf = KeyFactory.getInstance("RSA");
        for (var keyNode : node.get("keys")) {
            if ("active".equals(keyNode.get("status").asText())) {
                String kid = keyNode.get("kid").asText();
                String privPem = keyNode.get("private_key_pem").asText()
                    .replaceAll("-----.*?-----", "").replaceAll("\\s+", "");
                String pubPem = keyNode.get("public_key_pem").asText()
                    .replaceAll("-----.*?-----", "").replaceAll("\\s+", "");
                RSAPrivateKey privateKey = (RSAPrivateKey) kf.generatePrivate(
                    new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privPem)));
                RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(pubPem)));
                activeKey = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(kid)
                    .build();
                break;
            }
        }
        if (activeKey == null) throw new IllegalStateException("No active signing key found in secret");
    }

    public String signIdToken(String sub, String clientId, long totpEnrolledAt) {
        long now = Instant.now().getEpochSecond();
        var claims = new JWTClaimsSet.Builder()
            .issuer(issuer).subject(sub).audience(clientId)
            .issueTime(new Date(now * 1000)).expirationTime(new Date((now + 3600) * 1000))
            .claim("amr", List.of("totp"))
            .claim("totp_enrolled_at", totpEnrolledAt)
            .build();
        return sign(claims);
    }

    public String signAccessToken(String sub, String clientId) {
        long now = Instant.now().getEpochSecond();
        var claims = new JWTClaimsSet.Builder()
            .issuer(issuer).subject(sub).audience("https://api.tokido.io")
            .issueTime(new Date(now * 1000)).expirationTime(new Date((now + 3600) * 1000))
            .claim("scope", "totp").claim("client_id", clientId)
            .build();
        return sign(claims);
    }

    private String sign(JWTClaimsSet claims) {
        try {
            var jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(activeKey.getKeyID()).build(),
                claims);
            jwt.sign(new RSASSASigner(activeKey));
            return jwt.serialize();
        } catch (JOSEException e) { throw new RuntimeException(e); }
    }

    public List<Map<String, Object>> publicJwks() {
        var pub = activeKey.toPublicJWK();
        return List.of(Map.of(
            "kty", "RSA",
            "use", "sig",
            "alg", "RS256",
            "kid", pub.getKeyID(),
            "n",   pub.getModulus().toString(),
            "e",   pub.getPublicExponent().toString()
        ));
    }
}
