package com.labs.formauth.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ErrorPagesController {

    @GetMapping("/403")
    public String forbidden() {
        return "403";
    }
}