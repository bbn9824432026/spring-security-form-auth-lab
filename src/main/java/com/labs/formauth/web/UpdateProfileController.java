package com.labs.formauth.web;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

// Throwaway trigger point only - a POST-only, state-changing endpoint,
// exists purely to reproduce the "method is never replayed" trap.
@RestController
public class UpdateProfileController {

    @PostMapping("/profile/update")
    public String updateProfile(@RequestParam("bio") String bio, Authentication authentication) {
        System.out.println("[2.8] POST /profile/update ACTUALLY EXECUTED for "
                + authentication.getName() + ", bio=" + bio);
        return "Profile updated for " + authentication.getName() + ": " + bio;
    }
}