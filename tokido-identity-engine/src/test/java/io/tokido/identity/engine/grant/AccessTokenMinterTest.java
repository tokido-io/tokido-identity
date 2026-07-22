package io.tokido.identity.engine.grant;

import com.nimbusds.jwt.SignedJWT;
import io.tokido.identity.claims.ClaimsContext;
import io.tokido.identity.claims.ClaimsEnricher;
import io.tokido.identity.client.ClientAuthenticationMethod;
import io.tokido.identity.client.RegisteredClient;
import io.tokido.identity.config.DiscoveryConfig;
import io.tokido.identity.engine.signing.NimbusTokenSigner;
import io.tokido.identity.grant.AccessTokenRequest;
import io.tokido.identity.grant.MintedToken;
import io.tokido.identity.key.KeyStore;
import io.tokido.identity.test.Fixtures;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class AccessTokenMinterTest {

    private static final RegisteredClient CLIENT = new RegisteredClient("c1", "hash",
            Set.of("client_credentials"), Set.of("read", "write"),
            Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));

    private final Clock clock = Fixtures.fixedClock();
    private final KeyStore keyStore = Fixtures.singleKeyStore(Fixtures.rsaSigningKey("kid-1"));
    private final DiscoveryConfig config = new DiscoveryConfig(URI.create("https://idp.example.com"));

    private AccessTokenMinter minter(List<ClaimsEnricher> enrichers, Set<String> defaultAud) {
        return new AccessTokenMinter(new NimbusTokenSigner(), keyStore, config, clock,
                Duration.ofHours(1), defaultAud, () -> "jti-123", enrichers);
    }

    private static AccessTokenRequest request(Set<String> scopes, Set<String> aud) {
        return new AccessTokenRequest("client_credentials", CLIENT, "c1", scopes, aud, Map.of());
    }

    @Test
    void mints_token_with_expected_claims() throws Exception {
        MintedToken token = minter(List.of(), Set.of("https://idp.example.com"))
                .mintAccessToken(request(Set.of("read", "write"), Set.of()));

        assertThat(token.value().split("\\.")).hasSize(3);
        assertThat(token.issuedAt()).isEqualTo(clock.instant());
        assertThat(token.expiresAt()).isEqualTo(clock.instant().plusSeconds(3600));

        var claims = SignedJWT.parse(token.value()).getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo("https://idp.example.com");
        assertThat(claims.getSubject()).isEqualTo("c1");
        assertThat(claims.getStringClaim("client_id")).isEqualTo("c1");
        assertThat(claims.getJWTID()).isEqualTo("jti-123");
        assertThat(claims.getIssueTime().toInstant()).isEqualTo(clock.instant());
        assertThat(claims.getExpirationTime().toInstant()).isEqualTo(clock.instant().plusSeconds(3600));
        assertThat(claims.getStringClaim("scope")).isEqualTo("read write"); // sorted, space-delimited
        assertThat(claims.getAudience()).containsExactly("https://idp.example.com"); // default used
    }

    @Test
    void uses_request_audience_when_present() throws Exception {
        MintedToken token = minter(List.of(), Set.of("https://default"))
                .mintAccessToken(request(Set.of("read"), Set.of("https://api.example.com")));
        var claims = SignedJWT.parse(token.value()).getJWTClaimsSet();
        assertThat(claims.getAudience()).containsExactly("https://api.example.com");
    }

    @Test
    void runs_enrichers_but_reserved_claims_win() throws Exception {
        ClaimsEnricher enricher = ctx -> Map.of("tenant", "acme", "sub", "HACK");
        MintedToken token = minter(List.of(enricher), Set.of("https://idp.example.com"))
                .mintAccessToken(request(Set.of("read"), Set.of()));
        var claims = SignedJWT.parse(token.value()).getJWTClaimsSet();
        assertThat(claims.getStringClaim("tenant")).isEqualTo("acme"); // enricher claim added
        assertThat(claims.getSubject()).isEqualTo("c1");               // reserved claim not clobbered
    }

    @Test
    void enricher_context_is_targeted_per_token() {
        var captured = new java.util.concurrent.atomic.AtomicReference<ClaimsContext>();
        ClaimsEnricher enricher = ctx -> {
            captured.set(ctx);
            return Map.of();
        };
        minter(List.of(enricher), Set.of("https://idp.example.com"))
                .mintAccessToken(request(Set.of("read"), Set.of()));
        ClaimsContext ctx = captured.get();
        assertThat(ctx.tokenType()).isEqualTo("access_token");
        assertThat(ctx.grantType()).isEqualTo("client_credentials");
        assertThat(ctx.client()).isSameAs(CLIENT);
        assertThat(ctx.subject()).isEqualTo("c1");
        assertThat(ctx.scopes()).containsExactly("read");
    }
}
