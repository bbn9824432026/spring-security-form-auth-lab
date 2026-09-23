package com.labs.formauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.RequestCache;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // FIRST in FilterChainProxy's list. MUST be scoped narrowly - an
    // unscoped chain defaults to matching everything, which would make
    // this chain swallow requests meant for the one below it too.
    @Order(1)
    @Bean
    public SecurityFilterChain apiFilterChain(HttpSecurity http,
                                              AuthenticationManager authenticationManager) throws Exception {
        http
                .securityMatcher("/api/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                // SAME AuthenticationManager as the form-login chain below -
                // same UserDetailsService, same DaoAuthenticationProvider, same
                // lockout guard (2.17), same audit listeners (2.16). One
                // identity source, two independent entry mechanisms.
                .authenticationManager(authenticationManager)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Correctly disabled - see Part A. Not Topic 2.1's shortcut.
                .csrf(csrf -> csrf.disable())
                .httpBasic(basic -> {});

        return http.build();
    }

    // SECOND. No .securityMatcher() call at all - its default scope really
    // is "everything," which is exactly correct PROVIDED it stays after
    // the narrower chain above. Everything else here is unchanged since
    // Topic 2.17.
    @Order(2)
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
                                           UserDetailsService userDetailsService) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/debug/**", "/403").permitAll()
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
                        .tokenValiditySeconds(1209600)
                        .rememberMeParameter("remember-me")
                        .userDetailsService(userDetailsService)
                );

        return http.build();
    }
}