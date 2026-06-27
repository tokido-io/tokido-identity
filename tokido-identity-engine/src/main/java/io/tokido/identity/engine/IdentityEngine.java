package io.tokido.identity.engine;

import io.tokido.identity.config.DiscoveryConfig;
import io.tokido.identity.key.KeyStore;
import io.tokido.identity.protocol.DiscoveryDocument;
import io.tokido.identity.protocol.JsonWebKeySet;

import java.time.Clock;
import java.util.Objects;

/**
 * The framework-free, deterministic protocol engine. v0.1 serves discovery and
 * JWKS. The injected {@link Clock} is the single time source (no wall-clock
 * calls anywhere in the engine), established now for later token increments.
 */
public final class IdentityEngine {

    private final DiscoveryConfig config;
    private final KeyStore keyStore;
    private final Clock clock;

    public IdentityEngine(DiscoveryConfig config, KeyStore keyStore, Clock clock) {
        this.config = Objects.requireNonNull(config, "config");
        this.keyStore = Objects.requireNonNull(keyStore, "keyStore");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public DiscoveryDocument discovery() {
        return Discovery.build(config, keyStore);
    }

    public JsonWebKeySet jwks() {
        return Jwks.from(keyStore);
    }

    public String discoveryJson() {
        return Json.write(discovery().toOrderedMap());
    }

    public String jwksJson() {
        return Json.write(jwks());
    }

    public Clock clock() {
        return clock;
    }

    // package-private: for cross-instance signing tests only; not public API.
    io.tokido.identity.key.SigningKey currentForTest() {
        return keyStore.currentSigningKey();
    }
}
