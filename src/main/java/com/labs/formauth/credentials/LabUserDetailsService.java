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

        UserDetails carol = User.withUsername("carol")
                .password(passwordEncoder.encode("password123"))
                .roles("USER")
                .credentialsExpired(true)
                .build();

        // Added in 2.11: an actual ROLE_ADMIN user, so sec:authorize has
        // something real to differ on - alice and dave will render home.html
        // differently, from the identical template.
        UserDetails dave = User.withUsername("dave")
                .password(passwordEncoder.encode("password123"))
                .roles("USER", "ADMIN")
                .build();

        return new InMemoryUserDetailsManager(alice, bob, carol, dave);
    }
}