package com.labs.formauth.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

// DELIBERATE CONTRAST — DO NOT USE IN PRODUCTION.
// Reveals account state to anyone who submits ANY password for a known
// username. Exists only to make Part A's trap undeniable.
public class LeakyAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        if (exception instanceof LockedException) {
            redirectStrategy.sendRedirect(request, response, "/login?reason=locked");
            return;
        }
        if (exception instanceof DisabledException) {
            redirectStrategy.sendRedirect(request, response, "/login?reason=disabled");
            return;
        }
        redirectStrategy.sendRedirect(request, response, "/login?reason=bad_credentials");
    }
}