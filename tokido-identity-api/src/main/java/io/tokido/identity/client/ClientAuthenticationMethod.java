package io.tokido.identity.client;

import org.apiguardian.api.API;

import java.util.Locale;
import java.util.Objects;

/**
 * Token-endpoint client authentication methods supported in v0.2. The wire value
 * (RFC 6749 / RFC 8414) is the lowercase enum name. {@code private_key_jwt} and
 * mTLS methods are deferred to a later increment.
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.2.0")
public enum ClientAuthenticationMethod {

    /** HTTP Basic authentication carrying {@code client_id:client_secret} (RFC 6749 §2.3.1). */
    CLIENT_SECRET_BASIC,

    /** {@code client_id} + {@code client_secret} in the form body (RFC 6749 §2.3.1). */
    CLIENT_SECRET_POST;

    /** The RFC wire value, e.g. {@code "client_secret_basic"}. */
    public String wireValue() {
        return name().toLowerCase(Locale.ROOT);
    }

    /**
     * Resolve a wire value to its enum constant.
     *
     * @param wireValue the RFC wire value; non-null
     * @return the matching method
     * @throws IllegalArgumentException if no method matches
     */
    public static ClientAuthenticationMethod fromWire(String wireValue) {
        Objects.requireNonNull(wireValue, "wireValue");
        for (ClientAuthenticationMethod m : values()) {
            if (m.wireValue().equals(wireValue)) {
                return m;
            }
        }
        throw new IllegalArgumentException("unknown token-endpoint auth method: " + wireValue);
    }
}
