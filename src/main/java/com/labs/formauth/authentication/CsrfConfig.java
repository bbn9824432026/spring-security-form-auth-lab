package com.labs.formauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

@Configuration
public class CsrfConfig {

    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        return new HttpSessionCsrfTokenRepository();

        // CONTRAST TOGGLE: for SPA/JS clients that need to read the token
        // themselves (no server-rendered <form> to inject it into) - see
        // the contrast experiment below.
        // return org.springframework.security.web.csrf.CookieCsrfTokenRepository.withHttpOnlyFalse();
    }
}