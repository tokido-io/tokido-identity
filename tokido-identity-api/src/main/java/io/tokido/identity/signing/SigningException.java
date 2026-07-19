package io.tokido.identity.signing;

import org.apiguardian.api.API;

/** Thrown when a {@link TokenSigner} cannot produce a signature. */
@API(status = API.Status.EXPERIMENTAL, since = "0.1.0")
public class SigningException extends RuntimeException {
    public SigningException(String message) {
        super(message);
    }

    public SigningException(String message, Throwable cause) {
        super(message, cause);
    }
}
