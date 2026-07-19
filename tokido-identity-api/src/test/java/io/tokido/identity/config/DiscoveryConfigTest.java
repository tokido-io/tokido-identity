package io.tokido.identity.config;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DiscoveryConfigTest {

    @Test
    void accepts_https_issuer() {
        DiscoveryConfig c = new DiscoveryConfig(URI.create("https://idp.example.com"));
        assertThat(c.issuer().toString()).isEqualTo("https://idp.example.com");
    }

    @Test
    void accepts_http_loopback_for_local_dev() {
        assertThat(new DiscoveryConfig(URI.create("http://localhost:8080")).issuer()).isNotNull();
        assertThat(new DiscoveryConfig(URI.create("http://127.0.0.1:8080")).issuer()).isNotNull();
        assertThat(new DiscoveryConfig(URI.create("http://[::1]:8080")).issuer()).isNotNull();
    }

    @Test
    void rejects_plain_http_non_loopback() {
        assertThatThrownBy(() -> new DiscoveryConfig(URI.create("http://idp.example.com")))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("https");
    }

    @Test
    void rejects_query_or_fragment() {
        assertThatThrownBy(() -> new DiscoveryConfig(URI.create("https://idp.example.com?x=1")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DiscoveryConfig(URI.create("https://idp.example.com#f")))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
