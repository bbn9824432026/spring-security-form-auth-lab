package com.labs.formauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;

@Configuration
public class SessionRegistryConfig {

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    // THE FIX for registry staleness on timeout (Part A, trap #2).
    // Deliberately commented out for Step 1's broken demonstration below.
    // @Bean
    // public org.springframework.security.web.session.HttpSessionEventPublisher httpSessionEventPublisher() {
    //     return new org.springframework.security.web.session.HttpSessionEventPublisher();
    // }
}