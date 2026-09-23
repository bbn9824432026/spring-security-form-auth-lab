package com.labs.formauth.authentication;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.io.IOException;

// Wraps exactly what .loginPage("/login") built invisibly since Topic 2.1 -
// same real object underneath, instrumented at the precise handoff point.
public class LabAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final AuthenticationEntryPoint delegate;

    public LabAuthenticationEntryPoint(String loginFormUrl) {
        this.delegate = new LoginUrlAuthenticationEntryPoint(loginFormUrl);
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        // This IS ExceptionTranslationFilter calling us, right after it cleared
        // the SecurityContext and saved the request (Topic 2.8's save point).
        System.out.println("[2.9] entry point commencing - exception class: "
                + authException.getClass().getSimpleName());
        System.out.println("[2.9] originally requested: " + request.getMethod() + " " + request.getRequestURI());

        delegate.commence(request, response, authException);

        System.out.println("[2.9] redirect issued -> " + response.getHeader("Location"));
    }
}