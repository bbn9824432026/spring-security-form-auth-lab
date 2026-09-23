package com.labs.formauth.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;

import java.io.IOException;

public class LabAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {

        System.out.println("[2.7] internal audit -> " + exception.getClass().getSimpleName()
                + " : " + exception.getMessage());

        if (exception instanceof CredentialsExpiredException) {
            redirectStrategy.sendRedirect(request, response, "/login?expired");
            return;
        }

        // Added in 2.14: this ONLY fires after the password already checked
        // out (Topic 2.13's ConcurrentSessionControlAuthenticationStrategy
        // runs post-success) - the exact same safe-to-reveal category as
        // CredentialsExpiredException above, for the exact same reason.
        if (exception instanceof org.springframework.security.web.authentication.session.SessionAuthenticationException) {
            redirectStrategy.sendRedirect(request, response, "/login?too-many-sessions");
            return;
        }

        if (exception instanceof LockedException
                || exception instanceof DisabledException
                || exception instanceof AccountExpiredException) {
            redirectStrategy.sendRedirect(request, response, "/login?error");
            return;
        }

        redirectStrategy.sendRedirect(request, response, "/login?error");
    }
}