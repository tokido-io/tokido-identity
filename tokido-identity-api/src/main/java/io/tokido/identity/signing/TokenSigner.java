package io.tokido.identity.signing;

import io.tokido.identity.key.SigningKey;
import org.apiguardian.api.API;

/**
 * SPI for producing a compact JWS over a JSON claims payload. Algorithm-agnostic:
 * the algorithm is carried on the {@link SigningKey}, never on this signature, so
 * new algorithms are additive. The default Nimbus implementation lives in the
 * engine module; custom (KMS/HSM) signers depend only on this API module.
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.1.0")
public interface TokenSigner {

    /**
     * Sign {@code claimsJson} with {@code key} and return the compact JWS.
     *
     * @param claimsJson JSON claims set payload
     * @param key        the signing key (provides algorithm, kid, private key)
     * @return compact-serialized JWS
     * @throws SigningException if signing fails
     */
    String sign(String claimsJson, SigningKey key);
}
