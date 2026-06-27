package io.tokido.identity.spring;

import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IssuerValidationTest {

    @SpringBootApplication
    static class App {
    }

    @Test
    void missing_issuer_fails_fast() {
        SpringApplication app = new SpringApplication(App.class);
        app.setWebApplicationType(WebApplicationType.NONE);
        assertThatThrownBy(() -> app.run("--tokido.identity.dev-keys=true"))
                .hasMessageContaining("tokido.identity.issuer");
    }

    @Test
    void dev_keys_disabled_without_keystore_fails_fast() {
        SpringApplication app = new SpringApplication(App.class);
        app.setWebApplicationType(WebApplicationType.NONE);
        assertThatThrownBy(() -> app.run("--tokido.identity.issuer=https://idp.example.com"))
                .hasMessageContaining("dev-keys");
    }
}
