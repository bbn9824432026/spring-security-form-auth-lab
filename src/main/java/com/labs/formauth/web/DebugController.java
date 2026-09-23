package com.labs.formauth.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
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

    public DebugController(RequestCache requestCache, SessionRegistry sessionRegistry) {
        this.requestCache = requestCache;
        this.sessionRegistry = sessionRegistry;
    }

    @GetMapping("/debug/saved-request")
    public String showSavedRequest(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest saved = requestCache.getRequest(request, response);
        if (saved == null) {
            return "[2.8] no saved request in this session";
        }
        String params = saved.getParameterMap().entrySet().stream()
                .map(e -> e.getKey() + "=" + String.join(",", e.getValue()))
                .collect(Collectors.joining("; "));
        return "[2.8] method=" + saved.getMethod()
                + " | redirectUrl=" + saved.getRedirectUrl()
                + " | parameters={" + params + "}";
    }

    @GetMapping("/debug/session")
    public String showSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return "[2.12] no session exists for this request";
        }
        return "[2.12] session exists - id=" + session.getId();
    }

    // Added in 2.14 - direct proof of what the registry actually believes
    // is currently active for a given username, including stale entries.
    @GetMapping("/debug/sessions/{username}")
    public String showSessionsForUser(@PathVariable String username) {
        for (Object principal : sessionRegistry.getAllPrincipals()) {
            String principalName = (principal instanceof UserDetails ud) ? ud.getUsername() : principal.toString();
            if (principalName.equals(username)) {
                List<SessionInformation> sessions = sessionRegistry.getAllSessions(principal, true);
                if (sessions.isEmpty()) {
                    return "[2.14] registry has principal '" + username + "' but no session entries";
                }
                return sessions.stream()
                        .map(si -> "sessionId=" + si.getSessionId()
                                + ", expired=" + si.isExpired()
                                + ", lastRequest=" + si.getLastRequest())
                        .collect(Collectors.joining("\n"));
            }
        }
        return "[2.14] no registry entries found for " + username;
    }
}