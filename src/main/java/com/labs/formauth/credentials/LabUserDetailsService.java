package com.labs.formauth.credentials;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class LabUserDetailsService {

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails alice = User.withUsername("alice")
                .password(passwordEncoder.encode("password123"))
                .roles("USER")
                .build();

        UserDetails bob = User.withUsername("bob")
                .password(passwordEncoder.encode("password123"))
                .roles("USER")
                .accountLocked(true)
                .build();

        // Added in 2.7: correct password, expired credentials - the ONE
        // status exception that only ever fires AFTER a correct password.
        UserDetails carol = User.withUsername("carol")
                .password(passwordEncoder.encode("password123"))
                .roles("USER")
                .credentialsExpired(true)
                .build();

        return new InMemoryUserDetailsManager(alice, bob, carol);
    }
}