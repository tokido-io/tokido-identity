package io.tokido.identity.engine;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class JsonTest {
    @Test
    void writes_ordered_object() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("issuer", "https://idp");
        m.put("flag", false);
        String json = Json.write(m);
        assertThat(json).contains("\"issuer\":\"https://idp\"").contains("\"flag\":false");
    }
}
