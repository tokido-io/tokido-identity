package io.tokido.identity.engine;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import io.tokido.identity.key.KeyStore;
import io.tokido.identity.key.VerificationKey;
import io.tokido.identity.protocol.JsonWebKey;
import io.tokido.identity.protocol.JsonWebKeySet;

import java.security.interfaces.RSAPublicKey;
import java.util.List;

/** Builds a public {@link JsonWebKeySet} from a {@link KeyStore}'s verification keys. */
public final class Jwks {

    private Jwks() {
    }

    public static JsonWebKeySet from(KeyStore store) {
        List<JsonWebKey> keys = store.verificationKeys().stream()
                .map(Jwks::toJwk)
                .toList();
        return new JsonWebKeySet(keys);
    }

    private static JsonWebKey toJwk(VerificationKey key) {
        RSAKey jwk = new RSAKey.Builder((RSAPublicKey) key.publicKey())
                .keyID(key.kid())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build()
                .toPublicJWK();
        // toJSONObject() on a public JWK contains only public params; JsonWebKey re-checks.
        return new JsonWebKey(jwk.toJSONObject());
    }
}
