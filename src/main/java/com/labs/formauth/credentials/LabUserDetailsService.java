package com.labs.formauth.credentials;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

//@Configuration
public class LabUserDetailsService {

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails alice = User.withUsername("alice")
                .password(passwordEncoder.encode("password123"))
                .roles("USER")
                .build();

        // Added in 2.4: a second account with a status flag actually SET,
        // so the pre-authentication checks from Topic 2.3 have something
        // real to reject instead of being taken on faith.
        UserDetails bob = User.withUsername("bob")
                .password(passwordEncoder.encode("password123"))
                .roles("USER")
                .accountLocked(true)   // isAccountNonLocked() will now return false
                .build();

        // InMemoryUserDetailsManager stores these in an internal map and,
        // notably, normalizes usernames to lowercase internally - see
        // Try It Yourself #2.
        return new InMemoryUserDetailsManager(alice, bob);
    }
}