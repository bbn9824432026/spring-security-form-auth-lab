package com.labs.formauth.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    // Spring Security's LoginUrlAuthenticationEntryPoint only guarantees the
    // redirect. It does NOT generate a page for a custom loginPage() — you
    // own the rendering, which is why this mapping has to exist at all.
    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }
}