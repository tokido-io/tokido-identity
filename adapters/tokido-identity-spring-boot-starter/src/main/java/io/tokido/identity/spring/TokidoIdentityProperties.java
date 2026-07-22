package io.tokido.identity.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/** Configuration for the Tokido Identity starter. */
@ConfigurationProperties(prefix = "tokido.identity")
public class TokidoIdentityProperties {

    /** Issuer base URL; required. Drives all advertised endpoint URLs. */
    private String issuer;

    /** Opt-in to the ephemeral dev KeyStore. Never enable in production. */
    private boolean devKeys = false;

    /** Access-token lifetime; default one hour. */
    private Duration accessTokenTtl = Duration.ofHours(1);

    /** Access-token audience ({@code aud}); when unset, defaults to the issuer. */
    private String tokenAudience;

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

    public Duration getAccessTokenTtl() {
        return accessTokenTtl;
    }

    public void setAccessTokenTtl(Duration accessTokenTtl) {
        this.accessTokenTtl = accessTokenTtl;
    }

    public String getTokenAudience() {
        return tokenAudience;
    }

    public void setTokenAudience(String tokenAudience) {
        this.tokenAudience = tokenAudience;
    }
}
