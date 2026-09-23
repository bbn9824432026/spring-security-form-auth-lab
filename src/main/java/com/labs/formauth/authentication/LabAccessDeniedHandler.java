package com.labs.formauth.authentication;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;

import java.io.IOException;
import java.util.Optional;

// A COMPLETELY DIFFERENT object from LabAuthenticationEntryPoint above -
// this only runs for an authenticated, non-anonymous principal who is
// missing a specific permission. formLogin() has no involvement here at all.
public class LabAccessDeniedHandler implements AccessDeniedHandler {

    private final AccessDeniedHandlerImpl delegate = new AccessDeniedHandlerImpl();

    public LabAccessDeniedHandler() {
        delegate.setErrorPage("/403"); // forwards here, preserving 403 status
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        String principal = Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
                .map(a -> a.getName())
                .orElse("none");
        System.out.println("[2.9] AccessDeniedHandler invoked (NOT the entry point) - principal: " + principal);
        System.out.println("[2.9] denied reason: " + accessDeniedException.getMessage());

        delegate.handle(request, response, accessDeniedException);
    }
}