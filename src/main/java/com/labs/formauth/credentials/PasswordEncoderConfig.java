package com.labs.formauth.credentials;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

// Minimal scaffold only. Full treatment (encoding IDs, BCrypt internals,
// why DelegatingPasswordEncoder exists) is Topic 2.5. This bean exists
// here only so something can encode/check the demo password below.
@Configuration
public class PasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}