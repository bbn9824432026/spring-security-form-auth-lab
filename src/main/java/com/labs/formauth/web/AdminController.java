package com.labs.formauth.web;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

// Minimal trigger point ONLY - just enough authorization to produce a real
// AccessDeniedException for this topic. Full authorization rules, matcher
// types, and role hierarchies remain Group 3's subject.
@RestController
public class AdminController {

    @GetMapping("/admin")
    @ResponseBody
    public String admin(Authentication authentication) {
        return "Welcome, admin " + authentication.getName();
    }
}