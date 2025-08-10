package org.traning.loginviajwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/test")
public class TestController {
    private static final Logger logger = LoggerFactory.getLogger(TestController.class);

    @GetMapping("/auth")
    public ResponseEntity<?> testAuth() {
        logger.debug("=== /api/test/auth endpoint called ===");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        logger.debug("Authentication object: {}", authentication);
        
        if (authentication == null) {
            logger.warn("No authentication found in SecurityContext");
            return ResponseEntity.ok(Map.of("status", "unauthenticated", "message", "No authentication found"));
        }
        
        logger.debug("Principal class: {}", authentication.getPrincipal().getClass().getName());
        logger.debug("Principal: {}", authentication.getPrincipal());
        logger.debug("Authorities: {}", authentication.getAuthorities());
        
        Map<String, Object> response = new HashMap<>();
        response.put("authenticated", authentication.isAuthenticated());
        response.put("name", authentication.getName());
        response.put("authorities", authentication.getAuthorities().toString());
        response.put("principalType", authentication.getPrincipal().getClass().getName());
        
        if (authentication.getPrincipal() instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            response.put("username", userDetails.getUsername());
            response.put("userAuthorities", userDetails.getAuthorities());
        }
        
        return ResponseEntity.ok(response);
    }
}
