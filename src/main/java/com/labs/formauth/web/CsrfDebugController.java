package com.labs.formauth.web;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// Debug-only, permitAll. Spring resolves CsrfToken as a controller argument
// directly - and calling .getToken() on it HERE is exactly the act that
// resolves the deferred supplier from Part A.
@RestController
public class CsrfDebugController {

    @GetMapping("/debug/csrf")
    public String showCsrfToken(CsrfToken token) {
        return "[2.10] headerName=" + token.getHeaderName()
                + " | parameterName=" + token.getParameterName()
                + " | token=" + token.getToken();
    }
}