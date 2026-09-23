package com.labs.formauth.logout;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
public class LogoutConfig {

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return new LabLogoutSuccessHandler();
    }
}