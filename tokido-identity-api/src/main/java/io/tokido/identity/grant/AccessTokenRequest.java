package io.tokido.identity.grant;

import org.apiguardian.api.API;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Instruction to a {@link TokenMinter} describing the access token to mint. The
 * minter owns the protocol-critical claims ({@code iss}, {@code iat}, {@code exp},
 * {@code jti}); this request supplies the grant-decided values. {@code
 * additionalClaims} is an extension escape hatch; the minter will not let it
 * override reserved protocol claims.
 *
 * @param subject          the {@code sub} claim (for client_credentials, the client id); non-null, non-blank
 * @param clientId         the {@code client_id} claim; non-null, non-blank
 * @param scopes           the granted scopes; non-null, immutable
 * @param audiences        the {@code aud} values (empty → the minter's configured default); non-null, immutable
 * @param additionalClaims extra claims to include, subject to reserved-claim protection; non-null, immutable
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.2.0")
public record AccessTokenRequest(
        String subject,
        String clientId,
        Set<String> scopes,
        Set<String> audiences,
        Map<String, Object> additionalClaims) {

    public AccessTokenRequest {
        Objects.requireNonNull(subject, "subject");
        if (subject.isBlank()) {
            throw new IllegalArgumentException("subject must not be blank");
        }
        Objects.requireNonNull(clientId, "clientId");
        if (clientId.isBlank()) {
            throw new IllegalArgumentException("clientId must not be blank");
        }
        scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
        audiences = audiences == null ? Set.of() : Set.copyOf(audiences);
        additionalClaims = additionalClaims == null ? Map.of() : Map.copyOf(additionalClaims);
    }
}
