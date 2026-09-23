package com.labs.formauth.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.stream.Collectors;

// Debug-only, permitAll - exists purely to make RequestCache's internal
// state observable instead of taken on faith. Never ship this in a real app.
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
}