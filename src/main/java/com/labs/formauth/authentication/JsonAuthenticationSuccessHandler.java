package com.labs.formauth.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.List;
import java.util.Map;

// TOGGLE-ONLY contrast (see SuccessHandlerConfig). Proves onAuthenticationSuccess
// is not obligated to redirect at all - a real requirement for SPA/API clients
// expecting a JSON body, not a 302.
public class JsonAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        List<String> authorities = authentication.getAuthorities().stream()
                .map(Object::toString)
                .toList();

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(
                Map.of("status", "ok", "username", authentication.getName(), "authorities", authorities)
        ));
        // No redirect, no Location header. The entire "where do we send the
        // browser" question this topic covers simply doesn't apply here.
    }
}