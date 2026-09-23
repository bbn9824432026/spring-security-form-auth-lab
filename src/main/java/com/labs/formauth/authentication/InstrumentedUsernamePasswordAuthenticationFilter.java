package com.labs.formauth.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// This IS the real class .formLogin() built for you invisibly in Topic 2.1.
// We're subclassing it purely to print at the exact moments Part A described —
// nothing about the actual authentication behavior changes.
public class InstrumentedUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        // obtainUsername/obtainPassword = request.getParameter(...) under the hood.
        // This only runs at all because requiresAuthentication() already matched
        // path + method — that gate happened before this method was ever called.
        String username = obtainUsername(request);
        String password = obtainPassword(request);
        System.out.println("[2.2] extracted from POST body -> username='" + username
                + "', password present=" + (password != null));

        // super.attemptAuthentication() is where UsernamePasswordAuthenticationToken
        // .unauthenticated(username, password) gets built, then handed straight to
        // AuthenticationManager.authenticate(...). Everything happens inside this
        // one call - Topic 2.3 is what happens on the other side of it.
        Authentication result = super.attemptAuthentication(request, response);

        System.out.println("[2.2] AuthenticationManager returned -> "
                + result.getClass().getSimpleName()
                + ", authenticated=" + result.isAuthenticated()
                + ", authorities=" + result.getAuthorities());
        System.out.println("[2.2] attached details -> " + result.getDetails());
        // getDetails() is a WebAuthenticationDetails object — remote IP + session ID —
        // attached automatically, useful later for audit logging (Topic 2.16).

        return result;
    }
}