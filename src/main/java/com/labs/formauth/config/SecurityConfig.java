package com.labs.formauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

// @Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // Scaffolding only — matcher-based rules are Group 3's subject.
                // For this lab: no session, no access, period.
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        // Part A step 1: the 302 challenge needs a Location header value.
                        .loginPage("/login")

                        // Part A step 2: exact URL+method the auth filter listens on.
                        .loginProcessingUrl("/perform_login")

                        // Part A step 2: which parsed form-body keys to read.
                        .usernameParameter("user")
                        .passwordParameter("pass")

                        // Part A step 3: success redirect. false = prefer a saved
                        // deep link over this fixed URL when one exists.
                        .defaultSuccessUrl("/", false)

                        // Part A step 3: failure redirect.
                        .failureUrl("/login?error")

                        // Part A step 4 (the trap): without this, anyRequest()
                        // .authenticated() above blocks /login itself -> infinite
                        // redirect loop. This keeps all three URLs in sync automatically.
                        .permitAll()
                )
                // TEMPORARY. login.html has no CSRF token yet. Topic 2.10 explains
                // CsrfFilter properly and turns this back on with the Thymeleaf
                // sec: dialect. Leaving CSRF on right now would 403 every POST
                // to /perform_login before it even reached the auth filter.
                .csrf(csrf -> csrf.disable());

        return http.build();
    }
}