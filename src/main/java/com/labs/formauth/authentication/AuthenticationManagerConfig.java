package com.labs.formauth.authentication;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@Configuration
public class AuthenticationManagerConfig {

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService,
                                                               PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    // NOT provided automatically just because spring-security is on the
    // classpath - Boot only wires this for you along the auto-configured
    // AuthenticationManagerBuilder path, which building ProviderManager
    // by hand (below) bypasses entirely. Without this bean, the manager
    // falls back to its internal no-op publisher - silently, with no error.
    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        return new DefaultAuthenticationEventPublisher(applicationEventPublisher);
    }

    @Bean
    public AuthenticationManager authenticationManager(DaoAuthenticationProvider daoAuthenticationProvider,
                                                       BackupCredentialsAuthenticationProvider backupProvider,
                                                       AuthenticationEventPublisher authenticationEventPublisher) {
        ProviderManager manager = new ProviderManager(List.of(daoAuthenticationProvider, backupProvider));
        manager.setEraseCredentialsAfterAuthentication(true);

        // THE FIX - without this single line, every login attempt in this
        // project, since Topic 2.3, has published nothing at all.
        manager.setAuthenticationEventPublisher(authenticationEventPublisher);

        return manager;
    }
}