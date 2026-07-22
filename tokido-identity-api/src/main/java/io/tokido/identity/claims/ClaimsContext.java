package io.tokido.identity.claims;

import io.tokido.identity.client.RegisteredClient;
import org.apiguardian.api.API;

import java.util.Objects;
import java.util.Set;

/**
 * The context of a single token being minted, handed to each {@link ClaimsEnricher}
 * so enrichment is <strong>targeted per token</strong>: an enricher can vary its
 * claims by token type, grant type, client, subject, and granted scopes.
 *
 * @param tokenType the kind of token, e.g. {@code "access_token"}; non-null, non-blank
 * @param grantType the grant that produced it, e.g. {@code "client_credentials"}; non-null, non-blank
 * @param client    the client the token is for; non-null
 * @param subject   the {@code sub} of the token; non-null, non-blank
 * @param scopes    the granted scopes; non-null, immutable
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.2.0")
public record ClaimsContext(
        String tokenType,
        String grantType,
        RegisteredClient client,
        String subject,
        Set<String> scopes) {

    public ClaimsContext {
        Objects.requireNonNull(tokenType, "tokenType");
        if (tokenType.isBlank()) {
            throw new IllegalArgumentException("tokenType must not be blank");
        }
        Objects.requireNonNull(grantType, "grantType");
        if (grantType.isBlank()) {
            throw new IllegalArgumentException("grantType must not be blank");
        }
        Objects.requireNonNull(client, "client");
        Objects.requireNonNull(subject, "subject");
        if (subject.isBlank()) {
            throw new IllegalArgumentException("subject must not be blank");
        }
        scopes = Set.copyOf(Objects.requireNonNull(scopes, "scopes"));
    }
}
