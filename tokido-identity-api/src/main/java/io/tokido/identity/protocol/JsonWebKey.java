package io.tokido.identity.protocol;

import org.apiguardian.api.API;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * An RFC 7517 JSON Web Key as its wire-format member map. By construction this
 * type can hold only public material: any RSA/EC private parameter is rejected,
 * so a {@code JsonWebKey} can never leak a private key into JWKS.
 *
 * @param members the JWK members ({@code kty}, {@code kid}, {@code use}, {@code alg}, {@code n}, {@code e}, ...); non-null
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.1.0")
public record JsonWebKey(Map<String, Object> members) {

    private static final Set<String> PRIVATE_PARAMS = Set.of("d", "p", "q", "dp", "dq", "qi", "k");

    public JsonWebKey {
        Objects.requireNonNull(members, "members");
        if (!members.containsKey("kty") || !members.containsKey("kid")) {
            throw new IllegalArgumentException("JWK must contain kty and kid");
        }
        for (String p : PRIVATE_PARAMS) {
            if (members.containsKey(p)) {
                throw new IllegalArgumentException("JWK must not contain private parameter '" + p + "'");
            }
        }
        members = Map.copyOf(members);
    }
}
