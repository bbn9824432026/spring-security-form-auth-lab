package com.labs.formauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
public class SuccessHandlerConfig {

    @Bean
    public AuthenticationSuccessHandler successHandler() {
        return new LabAuthenticationSuccessHandler();

        // TOGGLE: comment the line above, uncomment below, to see a
        // completely non-redirecting success handler in action instead.
        // return new JsonAuthenticationSuccessHandler();
    }
}