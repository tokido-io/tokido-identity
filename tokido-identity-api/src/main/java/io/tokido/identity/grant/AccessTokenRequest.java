package io.tokido.identity.grant;

import io.tokido.identity.client.RegisteredClient;
import org.apiguardian.api.API;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Instruction to a {@link TokenMinter} describing the access token to mint. It is
 * the full minting context: the minter derives protocol claims ({@code iss},
 * {@code iat}, {@code exp}, {@code jti}, {@code client_id}) and builds the
 * {@link io.tokido.identity.claims.ClaimsContext} from it before running
 * enrichers. {@code additionalClaims} is an extension escape hatch; the minter
 * will not let it override reserved protocol claims.
 *
 * <p>The {@code client_id} claim is taken from {@code client.clientId()}.
 *
 * @param grantType        the grant that produced this token, e.g. {@code "client_credentials"}; non-null, non-blank
 * @param client           the client the token is issued to; non-null
 * @param subject          the {@code sub} claim (for client_credentials, the client id); non-null, non-blank
 * @param scopes           the granted scopes; non-null, immutable
 * @param audiences        the {@code aud} values (empty → the minter's configured default); non-null, immutable
 * @param additionalClaims extra claims to include, subject to reserved-claim protection; non-null, immutable
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.2.0")
public record AccessTokenRequest(
        String grantType,
        RegisteredClient client,
        String subject,
        Set<String> scopes,
        Set<String> audiences,
        Map<String, Object> additionalClaims) {

    public AccessTokenRequest {
        Objects.requireNonNull(grantType, "grantType");
        if (grantType.isBlank()) {
            throw new IllegalArgumentException("grantType must not be blank");
        }
        Objects.requireNonNull(client, "client");
        Objects.requireNonNull(subject, "subject");
        if (subject.isBlank()) {
            throw new IllegalArgumentException("subject must not be blank");
        }
        scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
        audiences = audiences == null ? Set.of() : Set.copyOf(audiences);
        additionalClaims = additionalClaims == null ? Map.of() : Map.copyOf(additionalClaims);
    }
}
