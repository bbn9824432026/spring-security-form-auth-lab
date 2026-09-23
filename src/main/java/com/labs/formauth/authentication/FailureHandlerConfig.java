package com.labs.formauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

@Configuration
public class FailureHandlerConfig {

    @Bean
    public AuthenticationFailureHandler failureHandler() {
        return new LabAuthenticationFailureHandler();

        // TOGGLE for the contrast experiment below:
        // return new LeakyAuthenticationFailureHandler();
    }
}