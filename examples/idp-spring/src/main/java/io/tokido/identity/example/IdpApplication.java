package io.tokido.identity.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Minimal runnable Tokido Identity IdP example. */
@SpringBootApplication
public class IdpApplication {
    public static void main(String[] args) {
        SpringApplication.run(IdpApplication.class, args);
    }
}
