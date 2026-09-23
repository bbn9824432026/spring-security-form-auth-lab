package com.labs.formauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.RequestCache;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           AuthenticationManager authenticationManager,
                                           AuthenticationSuccessHandler successHandler,
                                           AuthenticationFailureHandler failureHandler,
                                           RequestCache requestCache,
                                           AuthenticationEntryPoint authenticationEntryPoint,
                                           AccessDeniedHandler accessDeniedHandler,
                                           CsrfTokenRepository csrfTokenRepository,
                                           LogoutSuccessHandler logoutSuccessHandler,
                                           SessionRegistry sessionRegistry,
                                           UserDetailsService userDetailsService,
                                           PersistentTokenRepository persistentTokenRepository) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/debug/**", "/403").permitAll()
                        // Changed in 2.15: plain hasRole("ADMIN") would let a
                        // remember-me-only dave straight through. This requires a
                        // GENUINELY fresh login too - see Part A's trap.
                        .requestMatchers("/admin").access(
                                new WebExpressionAuthorizationManager("hasRole('ADMIN') and isFullyAuthenticated()"))
                        .anyRequest().authenticated()
                )
                .authenticationManager(authenticationManager)
                .requestCache(cache -> cache.requestCache(requestCache))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/perform_login")
                        .usernameParameter("user")
                        .passwordParameter("pass")
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                        .permitAll()
                )
                .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository))
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(logoutSuccessHandler)
                        .deleteCookies("JSESSIONID")
                )
                .sessionManagement(session -> {
                    session.sessionFixation(fixation -> fixation.changeSessionId());
                    session.maximumSessions(1)
                            .maxSessionsPreventsLogin(true)
                            .expiredUrl("/login?expired-session")
                            .sessionRegistry(sessionRegistry);
                })
                .rememberMe(rememberMe -> rememberMe
                                .key("formAuthLabRememberMeKey")
                                .tokenValiditySeconds(1209600) // 14 days
                                .rememberMeParameter("remember-me")
                                .userDetailsService(userDetailsService)
                        // CONTRAST TOGGLE: uncomment to switch from stateless
                        // TokenBasedRememberMeServices to stateful
                        // PersistentTokenBasedRememberMeServices - see Part A/lab.
                        // .tokenRepository(persistentTokenRepository)
                );

        return http.build();
    }
}