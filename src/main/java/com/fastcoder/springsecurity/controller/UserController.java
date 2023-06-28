package com.fastcoder.springsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api")
public class UserController {


    @GetMapping("admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String getAdmin(Principal principal){
        return "Hello " + principal.getName();
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String getUser(Principal principal){
        return "Hello " + principal.getName();
    }

    @GetMapping("/clear")
    public String clearPrincipal(){
        SecurityContextHolder.clearContext();
        return "GoodBy !!" ;
    }

}
