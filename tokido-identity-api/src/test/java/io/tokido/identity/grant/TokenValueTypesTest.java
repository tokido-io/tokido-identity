package io.tokido.identity.grant;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenValueTypesTest {

    @Test
    void token_request_coalesces_nulls_and_copies() {
        TokenRequest r = new TokenRequest("client_credentials", null, null);
        assertThat(r.requestedScopes()).isEmpty();
        assertThat(r.parameters()).isEmpty();

        TokenRequest r2 = new TokenRequest("client_credentials", Set.of("a"), Map.of("k", "v"));
        assertThatThrownBy(() -> r2.requestedScopes().add("b"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void token_request_rejects_blank_grant_type() {
        assertThatThrownBy(() -> new TokenRequest(" ", Set.of(), Map.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void token_response_holds_fields() {
        TokenResponse r = new TokenResponse("jws", "Bearer", Duration.ofHours(1), Set.of("read"));
        assertThat(r.accessToken()).isEqualTo("jws");
        assertThat(r.tokenType()).isEqualTo("Bearer");
        assertThat(r.expiresIn()).isEqualTo(Duration.ofHours(1));
        assertThat(r.scope()).containsExactly("read");
    }

    @Test
    void access_token_request_coalesces_and_validates() {
        AccessTokenRequest a = new AccessTokenRequest("c1", "c1", null, null, null);
        assertThat(a.scopes()).isEmpty();
        assertThat(a.audiences()).isEmpty();
        assertThat(a.additionalClaims()).isEmpty();
        assertThatThrownBy(() -> new AccessTokenRequest(" ", "c1", Set.of(), Set.of(), Map.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void minted_token_requires_expiry_after_issuance() {
        Instant iat = Instant.parse("2026-06-26T00:00:00Z");
        assertThat(new MintedToken("jws", iat, iat.plusSeconds(3600)).expiresAt())
                .isEqualTo(iat.plusSeconds(3600));
        assertThatThrownBy(() -> new MintedToken("jws", iat, iat))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
