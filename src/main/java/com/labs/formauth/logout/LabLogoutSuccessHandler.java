package com.labs.formauth.logout;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

// Runs LAST - every default LogoutHandler (SecurityContextLogoutHandler,
// CookieClearingLogoutHandler, CsrfLogoutHandler) has already executed by
// the time this method is called. Same ordering pattern as 2.6's success
// handler running after SecurityContextRepository had already saved.
public class LabLogoutSuccessHandler implements LogoutSuccessHandler {

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) throws IOException {
        String who = (authentication != null) ? authentication.getName() : "unknown";
        System.out.println("[2.12] logout success handler running for: " + who);
        response.sendRedirect("/login?logout");
    }
}