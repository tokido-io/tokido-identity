package io.tokido.identity.engine.grant;

import io.tokido.identity.grant.GrantHandler;
import io.tokido.identity.grant.OAuthError;
import io.tokido.identity.grant.OAuthException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * Dispatch table from {@code grant_type} wire value to its {@link GrantHandler}.
 * Built once at wiring time from the registered handlers (built-in plus any
 * plugin-contributed). Duplicate grant types are a configuration error.
 */
public final class GrantRegistry {

    private final Map<String, GrantHandler> handlers = new LinkedHashMap<>();

    public GrantRegistry(List<GrantHandler> handlers) {
        Objects.requireNonNull(handlers, "handlers");
        for (GrantHandler handler : handlers) {
            String grantType = Objects.requireNonNull(handler.grantType(), "grantType");
            if (this.handlers.putIfAbsent(grantType, handler) != null) {
                throw new IllegalArgumentException("duplicate GrantHandler for grant_type: " + grantType);
            }
        }
    }

    /**
     * @param grantType the requested grant type
     * @return the handler for {@code grantType}
     * @throws OAuthException {@code unsupported_grant_type} if none is registered
     */
    public GrantHandler get(String grantType) {
        GrantHandler handler = handlers.get(grantType);
        if (handler == null) {
            throw new OAuthException(OAuthError.UNSUPPORTED_GRANT_TYPE, "unsupported grant type: " + grantType);
        }
        return handler;
    }

    /** The registered grant types, sorted — feeds {@code grant_types_supported} in discovery. */
    public Set<String> grantTypes() {
        return new TreeSet<>(handlers.keySet());
    }
}
