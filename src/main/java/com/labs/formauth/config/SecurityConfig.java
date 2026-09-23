package com.labs.formauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated()
                )
                // Wires OUR explicit ProviderManager (2.3) in place of the one
                // Spring Boot would otherwise build invisibly. Everything below
                // this point is unchanged from Topic 2.1.
                .authenticationManager(authenticationManager)
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/perform_login")
                        .usernameParameter("user")
                        .passwordParameter("pass")
                        .defaultSuccessUrl("/", false)
                        .failureUrl("/login?error")
                        .permitAll()
                )
                .csrf(csrf -> csrf.disable());

        return http.build();
    }
}