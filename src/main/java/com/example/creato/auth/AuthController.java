package com.example.creato.auth;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.creato.jwt.JwtTokenUtil;
import com.example.creato.users.CustomUserDetailsService;

import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@RestController
@RequestMapping("auth")
public class AuthController {

    @Autowired
    AuthenticationProvider authenticationManager;

    @Autowired
    JwtTokenUtil jwtUtils;

    @PostMapping("/signin")
    public String authenticateUser(@RequestBody LoginRequest loginRequest) throws Exception {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            System.out.println("OK");

        } catch (BadCredentialsException e) {
            System.out.println(e);
            throw new Exception("Incorrect username or password", e);
        }

        String jwt = jwtUtils.generateToken(loginRequest.getUsername());

        return jwt;
    }

}
