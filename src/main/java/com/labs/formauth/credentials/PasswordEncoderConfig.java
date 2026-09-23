package com.labs.formauth.credentials;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        // This is a DelegatingPasswordEncoder, not a plain BCryptPasswordEncoder.
        // encode() always uses bcrypt (today's default id) and prepends "{bcrypt}".
        // matches() ignores that default entirely and reads whatever {id} is
        // actually stored on the value being checked. See Topic 2.5.
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}