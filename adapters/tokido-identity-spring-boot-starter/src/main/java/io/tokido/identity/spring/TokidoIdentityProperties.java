package io.tokido.identity.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Configuration for the Tokido Identity starter. */
@ConfigurationProperties(prefix = "tokido.identity")
public class TokidoIdentityProperties {

    /** Issuer base URL; required. Drives all advertised endpoint URLs. */
    private String issuer;

    /** Opt-in to the ephemeral dev KeyStore. Never enable in production. */
    private boolean devKeys = false;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public boolean isDevKeys() {
        return devKeys;
    }

    public void setDevKeys(boolean devKeys) {
        this.devKeys = devKeys;
    }
}
