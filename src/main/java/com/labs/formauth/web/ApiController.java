package com.labs.formauth.web;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

    @GetMapping("/api/whoami")
    public String whoami(Authentication authentication) {
        return "[2.18] API chain - authenticated as " + authentication.getName()
                + ", authorities=" + authentication.getAuthorities();
    }
}