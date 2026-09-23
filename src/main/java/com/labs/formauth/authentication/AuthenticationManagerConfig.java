package com.labs.formauth.authentication;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Map;

@Configuration
public class AuthenticationManagerConfig {

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService,
                                                               PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public LoginAttemptGuardAuthenticationProvider loginAttemptGuardAuthenticationProvider(LoginAttemptTracker tracker) {
        return new LoginAttemptGuardAuthenticationProvider(tracker);
    }

    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        DefaultAuthenticationEventPublisher publisher = new DefaultAuthenticationEventPublisher(applicationEventPublisher);

        // THE FIX foreshadowed in Topic 2.16: exact-class matching means
        // AccountLockoutException (a LockedException SUBCLASS) would
        // otherwise never produce an audit event at all.
        publisher.setAdditionalExceptionMappings(Map.of(
                AccountLockoutException.class, AuthenticationFailureLockedEvent.class
        ));
        return publisher;
    }

    @Bean
    public AuthenticationManager authenticationManager(LoginAttemptGuardAuthenticationProvider loginAttemptGuardAuthenticationProvider,
                                                       DaoAuthenticationProvider daoAuthenticationProvider,
                                                       BackupCredentialsAuthenticationProvider backupProvider,
                                                       AuthenticationEventPublisher authenticationEventPublisher) {
        // ORDER MATTERS (Topic 2.3): the guard goes FIRST, so a locked
        // account never reaches Dao's PasswordEncoder.matches() at all.
        ProviderManager manager = new ProviderManager(
                List.of(loginAttemptGuardAuthenticationProvider, daoAuthenticationProvider, backupProvider));
        manager.setEraseCredentialsAfterAuthentication(true);
        manager.setAuthenticationEventPublisher(authenticationEventPublisher);
        return manager;
    }
}