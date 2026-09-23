package com.labs.formauth.config;

import com.labs.formauth.authentication.InstrumentedUsernamePasswordAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// GLASS-BOX variant. Everything .formLogin() did declaratively in 2.1,
// done here by hand, object by object, so the internals are visible.
//
// TO RUN THIS: comment out the @Configuration annotation (and the whole
// filterChain bean) in SecurityConfig.java first — only one SecurityFilterChain
// covering "any request" can be active at a time. Revert when you're done.
@Configuration
@EnableWebSecurity
public class DebugSecurityConfig {

    @Bean
    public SecurityFilterChain debugFilterChain(HttpSecurity http,
                                                AuthenticationConfiguration authConfig) throws Exception {

        // This is the exact same AuthenticationManager formLogin() would have
        // used internally — you're just obtaining it explicitly instead of
        // letting the DSL do it invisibly.
        var authenticationManager = authConfig.getAuthenticationManager();

        var authFilter = new InstrumentedUsernamePasswordAuthenticationFilter();
        authFilter.setAuthenticationManager(authenticationManager);
        authFilter.setFilterProcessesUrl("/perform_login");   // same as loginProcessingUrl()
        authFilter.setUsernameParameter("user");               // same as usernameParameter()
        authFilter.setPasswordParameter("pass");               // same as passwordParameter()
        authFilter.setAuthenticationSuccessHandler(
                (request, response, authentication) -> response.sendRedirect("/"));
        authFilter.setAuthenticationFailureHandler(
                (request, response, exception) -> response.sendRedirect("/login?error"));

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login").permitAll()   // formLogin() did this automatically via permitAll();
                        // by hand, you have to list it yourself
                        .anyRequest().authenticated()
                )
                // Places our filter at the exact chain position
                // UsernamePasswordAuthenticationFilter normally occupies.
                .addFilterAt(authFilter, UsernamePasswordAuthenticationFilter.class)
                .csrf(csrf -> csrf.disable());

        return http.build();
    }
}