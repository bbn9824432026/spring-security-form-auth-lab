package com.labs.formauth.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.stream.Collectors;

@RestController
public class DebugController {

    private final RequestCache requestCache;

    public DebugController(RequestCache requestCache) {
        this.requestCache = requestCache;
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

    @GetMapping("/debug/clear-saved-request")
    public String clearSavedRequest(HttpServletRequest request, HttpServletResponse response) {
        requestCache.removeRequest(request, response);
        return "[2.8] saved request cleared";
    }

    // Added in 2.12 - direct proof of server-side session state, used
    // before and after a logout attempt.
    @GetMapping("/debug/session")
    public String showSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false); // never manufacture one just to check
        if (session == null) {
            return "[2.12] no session exists for this request";
        }
        return "[2.12] session exists - id=" + session.getId();
    }
}