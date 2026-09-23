package com.labs.formauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

@Configuration
public class RememberMeConfig {

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        return new InMemoryPersistentTokenRepository();
    }
}