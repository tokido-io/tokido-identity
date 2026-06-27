package io.tokido.identity.protocol;

import org.apiguardian.api.API;

import java.util.List;
import java.util.Objects;

/**
 * RFC 7517 §5 JWK Set returned by the engine's JWKS endpoint.
 *
 * @param keys the keys; non-null
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.1.0")
public record JsonWebKeySet(List<JsonWebKey> keys) {
    public JsonWebKeySet {
        keys = List.copyOf(Objects.requireNonNull(keys, "keys"));
    }
}
