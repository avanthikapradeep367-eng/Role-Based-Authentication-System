package com.example.rbac_auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class RouteController {

    @GetMapping({
        "/login", "/register", "/user/dashboard",
        "/manager/login", "/manager/dashboard",
        "/admin/login", "/admin/dashboard"
    })
    public String forwardToHome() {
        return "forward:/index.html";
    }
}
