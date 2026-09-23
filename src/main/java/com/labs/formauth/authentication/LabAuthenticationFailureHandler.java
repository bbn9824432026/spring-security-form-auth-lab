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

import java.io.IOException;

// Production-safe pattern: log the REAL exception type internally, but
// collapse everything except CredentialsExpiredException into one generic
// external message. See Part A for exactly why.
public class LabAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {

        // Internal audit trail only - nobody outside the server sees this line.
        // Real event-based auditing (not just a print) is Topic 2.16.
        System.out.println("[2.7] internal audit -> " + exception.getClass().getSimpleName()
                + " : " + exception.getMessage());

        if (exception instanceof CredentialsExpiredException) {
            // Safe to reveal: this ONLY fires post-password-check (2.3).
            redirectStrategy.sendRedirect(request, response, "/login?expired");
            return;
        }

        if (exception instanceof LockedException
                || exception instanceof DisabledException
                || exception instanceof AccountExpiredException) {
            // NOT safe to reveal distinctly - these are pre-checks (2.3) and
            // fire even with a wrong password. Same external outcome as
            // plain bad credentials, on purpose.
            redirectStrategy.sendRedirect(request, response, "/login?error");
            return;
        }

        // BadCredentialsException, including the masked "unknown user" case
        // from Topic 2.4's hideUserNotFoundExceptions.
        redirectStrategy.sendRedirect(request, response, "/login?error");
    }
}