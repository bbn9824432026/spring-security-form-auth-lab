package com.labs.formauth.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
public class DebugController {

    private final RequestCache requestCache;
    private final SessionRegistry sessionRegistry;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    public DebugController(RequestCache requestCache, SessionRegistry sessionRegistry,
                           UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.requestCache = requestCache;
        this.sessionRegistry = sessionRegistry;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/debug/saved-request")
    public String showSavedRequest(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest saved = requestCache.getRequest(request, response);
        if (saved == null) return "[2.8] no saved request in this session";
        String params = saved.getParameterMap().entrySet().stream()
                .map(e -> e.getKey() + "=" + String.join(",", e.getValue()))
                .collect(Collectors.joining("; "));
        return "[2.8] method=" + saved.getMethod() + " | redirectUrl=" + saved.getRedirectUrl()
                + " | parameters={" + params + "}";
    }

    @GetMapping("/debug/session")
    public String showSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) return "[2.12] no session exists for this request";
        return "[2.12] session exists - id=" + session.getId();
    }

    @GetMapping("/debug/sessions/{username}")
    public String showSessionsForUser(@PathVariable String username) {
        for (Object principal : sessionRegistry.getAllPrincipals()) {
            String principalName = (principal instanceof UserDetails ud) ? ud.getUsername() : principal.toString();
            if (principalName.equals(username)) {
                List<SessionInformation> sessions = sessionRegistry.getAllSessions(principal, true);
                if (sessions.isEmpty()) return "[2.14] registry has principal but no session entries";
                return sessions.stream()
                        .map(si -> "sessionId=" + si.getSessionId() + ", expired=" + si.isExpired())
                        .collect(Collectors.joining("\n"));
            }
        }
        return "[2.14] no registry entries found for " + username;
    }

    // Added in 2.15 - direct proof of WHAT kind of Authentication this
    // request actually has, distinguishing a fresh login from remember-me.
    @GetMapping("/debug/whoami")
    public String whoami(Authentication authentication) {
        if (authentication == null) return "[2.15] no authentication in context";
        return "[2.15] class=" + authentication.getClass().getSimpleName()
                + " | name=" + authentication.getName()
                + " | isRememberMe=" + trustResolver.isRememberMe(authentication)
                + " | authorities=" + authentication.getAuthorities();
    }

    // LAB ONLY - never expose password changes over a bare GET in real code.
    // Exists purely to prove TokenBasedRememberMeServices invalidates on
    // password change, live, without building a real settings UI.
    @GetMapping("/debug/change-password/{username}/{newPassword}")
    public String changePassword(@PathVariable String username, @PathVariable String newPassword) {
        UserDetailsManager manager = (UserDetailsManager) userDetailsService;
        UserDetails current = manager.loadUserByUsername(username);
        UserDetails updated = User.withUserDetails(current)
                .password(passwordEncoder.encode(newPassword))
                .build();
        manager.updateUser(updated);
        return "[2.15] password updated for " + username;
    }
}