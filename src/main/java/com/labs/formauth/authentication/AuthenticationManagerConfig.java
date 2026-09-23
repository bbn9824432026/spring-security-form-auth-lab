package com.labs.formauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

// What Topic 2.1/2.2 were relying on invisibly, made explicit and controllable.
@Configuration
public class AuthenticationManagerConfig {

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService,
                                                               PasswordEncoder passwordEncoder) {
        // Constructor form - this IS what Boot was building for you silently.
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(DaoAuthenticationProvider daoAuthenticationProvider,
                                                       BackupCredentialsAuthenticationProvider backupProvider) {
        new BackupCredentialsAuthenticationProvider();
        // ORDER MATTERS - see the contrast experiment below.
        // Dao first, then Backup: matches how you'd normally rank "real" users
        // above emergency access.
        ProviderManager manager = new ProviderManager(List.of(daoAuthenticationProvider, backupProvider));

        // Explicit, even though true is the default - stated so it's visible,
        // not hidden behind a default you'd have to know to look for.
        manager.setEraseCredentialsAfterAuthentication(true);
        return manager;
    }

    @Bean
    public BackupCredentialsAuthenticationProvider backupProvider() {
        return new BackupCredentialsAuthenticationProvider();
    }

}