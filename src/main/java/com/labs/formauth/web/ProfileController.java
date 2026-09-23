package com.labs.formauth.web;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ProfileController {

    @GetMapping("/profile")
    public String profile(Authentication authentication, Model model) {
        model.addAttribute("username", authentication.getName());

        // Topic 2.4's central trap, made visible: getPrincipal() is NOT a
        // String by default - it's the full UserDetails object DaoAuthenticationProvider
        // retrieved and validated back in 2.3.
        Object principal = authentication.getPrincipal();
        System.out.println("[2.4] principal class -> " + principal.getClass().getName());
        System.out.println("[2.4] principal.toString() -> " + principal);
        // Uncomment to see it fail at runtime, not compile time:
        // String username = (String) principal;

        return "profile";
    }
}