package com.panda.security.feature.csrf.controller;

import com.panda.security.feature.csrf.service.CsrfTokenService;
import com.panda.security.feature.user.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Controller to expose the CSRF token to the frontend.
 * The token is read from the database (TokenType.CSRF) for the authenticated user.
 */
@RestController
@RequestMapping("/api/v1/csrf")
@RequiredArgsConstructor
public class CsrfController {

    private final CsrfTokenService csrfTokenService;

    /**
     * Endpoint to get the CSRF token.
     * The token is already present as a cookie (XSRF-TOKEN), but this endpoint
     * allows the frontend to verify that the cookie is still valid.
     *
     * @param user the authenticated user (automatically injected by Spring Security)
     * @return the CSRF token
     */
    @GetMapping("/token")
    public ResponseEntity<Map<String, String>> getCsrfToken(@AuthenticationPrincipal User user) {

        if (user == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "No authentication found. Please login first.");
            return ResponseEntity.status(401).body(error);
        }

        // Get the CSRF token from the database for the user
        String csrfToken = csrfTokenService.getCsrfTokenForUser(user);

        if (csrfToken == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "CSRF token not found. Please login again.");
            return ResponseEntity.status(401).body(error);
        }

        Map<String, String> response = new HashMap<>();
        response.put("token", csrfToken);
        response.put("headerName", "X-XSRF-TOKEN");
        response.put("parameterName", "_csrf");

        return ResponseEntity.ok(response);
    }
}

