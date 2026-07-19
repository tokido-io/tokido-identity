package io.tokido.identity.engine;

import com.nimbusds.jose.util.JSONObjectUtils;
import io.tokido.identity.protocol.JsonWebKey;
import io.tokido.identity.protocol.JsonWebKeySet;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** JSON serialization for engine outputs, via Nimbus's bundled JSON writer. */
public final class Json {

    private Json() {
    }

    /** Serialize an ordered map to a JSON object string. */
    public static String write(Map<String, Object> map) {
        return JSONObjectUtils.toJSONString(map);
    }

    /** Serialize a JWK Set to {@code {"keys":[...]}}. */
    public static String write(JsonWebKeySet set) {
        List<Object> keys = set.keys().stream().map(JsonWebKey::members).map(m -> (Object) m).toList();
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("keys", keys);
        return JSONObjectUtils.toJSONString(root);
    }
}
