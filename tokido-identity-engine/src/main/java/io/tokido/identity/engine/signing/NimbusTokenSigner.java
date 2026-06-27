package io.tokido.identity.engine.signing;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.tokido.identity.key.SigningKey;
import io.tokido.identity.signing.SigningException;
import io.tokido.identity.signing.TokenSigner;

import java.security.interfaces.RSAPrivateKey;

/**
 * Default {@link TokenSigner} backed by Nimbus JOSE+JWT. v0.1 supports RS256.
 * Ported from the auth-server harvest (signing primitive only): no claim
 * assembly, no key loading, no wall-clock — the engine supplies the key and the
 * claims JSON.
 */
public final class NimbusTokenSigner implements TokenSigner {

    @Override
    public String sign(String claimsJson, SigningKey key) {
        try {
            JWTClaimsSet claims = JWTClaimsSet.parse(claimsJson);
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.kid()).build(),
                    claims);
            jwt.sign(new RSASSASigner((RSAPrivateKey) key.privateKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new SigningException("failed to sign claims with kid " + key.kid(), e);
        }
    }
}
