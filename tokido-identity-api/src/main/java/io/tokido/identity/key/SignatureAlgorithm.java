package io.tokido.identity.key;

import org.apiguardian.api.API;

/**
 * JWS signature algorithms supported by the engine, named per RFC 7518.
 * The wire value equals the enum name. v0.1 supports RS256 only; further
 * algorithms are added additively.
 */
@API(status = API.Status.EXPERIMENTAL, since = "0.1.0")
public enum SignatureAlgorithm {
    /** RFC 7518 — RSASSA-PKCS1-v1_5 using SHA-256. */
    RS256
}
