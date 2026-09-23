package com.labs.formauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration
public class ExceptionHandlingConfig {

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new LabAuthenticationEntryPoint("/login");

        // TOGGLE for the contrast experiment below:
        // return new RestApiAuthenticationEntryPoint();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new LabAccessDeniedHandler();
    }
}