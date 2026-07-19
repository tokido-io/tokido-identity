package io.tokido.identity.spring;

import io.tokido.identity.key.KeyStore;
import io.tokido.identity.test.Fixtures;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = "tokido.identity.issuer=https://idp.example.com")
class BeanOverrideTest {

    @TestConfiguration
    static class CustomKeyStoreConfig {
        @Bean KeyStore keyStore() {
            return Fixtures.singleKeyStore(Fixtures.rsaSigningKey("custom-kid"));
        }
    }

    @Autowired KeyStore keyStore;

    @Test
    void consumer_keystore_overrides_default() {
        assertThat(keyStore.currentSigningKey().kid()).isEqualTo("custom-kid");
    }
}
