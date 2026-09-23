package com.labs.formauth.authentication;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;

// This IS what .defaultSuccessUrl("/", false) built invisibly in Topic 2.1 -
// written out by hand so every decision is visible.
public class LabAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final String defaultTargetUrl = "/";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        // By the time this line runs, SecurityContextRepository.saveContext()
        // (Group 1's 1.4 mechanism) has ALREADY persisted the session. This
        // handler runs LAST, not first - see the Try It Yourself trap below.
        System.out.println("[2.6] success handler running for: " + authentication.getName());
        System.out.println("[2.6] authorities: " + authentication.getAuthorities());

        // Exactly what SavedRequestAwareAuthenticationSuccessHandler checks
        // internally. Full RequestCache mechanics: Topic 2.8.
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        if (savedRequest != null) {
            String targetUrl = savedRequest.getRedirectUrl();
            System.out.println("[2.6] found saved request -> redirecting to " + targetUrl);
            redirectStrategy.sendRedirect(request, response, targetUrl);
            return;
        }

        System.out.println("[2.6] no saved request -> redirecting to default: " + defaultTargetUrl);
        redirectStrategy.sendRedirect(request, response, defaultTargetUrl);
    }
}