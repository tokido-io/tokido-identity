package io.tokido.identity.key;

import org.apiguardian.api.API;

import java.util.List;

/**
 * Source of token-signing keys for the engine. The single source of truth for
 * signing material; keys are external to the engine, never instance-local.
 *
 * <p>v0.1 is signing-only. The cookie-encryption key responsibility (parent
 * design D14) is a separate {@code EncryptionKeyStore} interface added in v0.3,
 * implemented by the same concrete store, so no encryption methods appear here.
 *
 * <p>Thread-safety: implementations must be safe for concurrent reads.
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.1.0")
public interface KeyStore {

    /**
     * The active signing key used to mint new tokens.
     *
     * @return the current signing key; never null
     */
    SigningKey currentSigningKey();

    /**
     * All public verification keys to publish in JWKS: the current key plus any
     * retained (rotated-out) keys kept for the rotation grace window.
     *
     * @return non-null, immutable, never-empty list
     */
    List<VerificationKey> verificationKeys();
}
