package com.panda.security.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final Logger LOGGER = LoggerFactory.getLogger(AuthenticationController.class);

    private final AuthenticationService service;

    @PostMapping(value = "/register", consumes = "application/json")
    public void register(@RequestBody RegisterRequest request) {
        LOGGER.info("POST /api/v1/auth/register - Registration request for email: {}", request.getEmail());
        try {
            service.register(request);
            LOGGER.info("POST /api/v1/auth/register - Registration completed successfully for email: {}", request.getEmail());
        } catch (Exception e) {
            LOGGER.error("POST /api/v1/auth/register - Error during registration for email: {} - Error: {}", request.getEmail(), e.getMessage(), e);
            throw e;
        }
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(Authentication authentication, HttpServletResponse response) {
        if (authentication == null || !authentication.isAuthenticated()) {
            LOGGER.warn("POST /api/v1/auth/authenticate - User not authorized");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String email = authentication.getName();
        try {
            service.authenticateAndSetCookies(authentication, response);
            LOGGER.debug("POST /api/v1/auth/authenticate - Authentication completed successfully for {} - Cookie impostati", email);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            LOGGER.error("POST /api/v1/auth/authenticate - {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        LOGGER.info("POST /api/v1/auth/refresh-token - Refresh token request");
        try {
            service.refreshToken(request, response);
            return ResponseEntity.ok().build();
        } catch (IOException ex) {
            LOGGER.error("POST /api/v1/auth/refresh-token - Error during refresh token - Error: {}", ex.getMessage(), ex);
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        LOGGER.info("POST /api/v1/auth/logout - Logout request");
        try {
            service.cleanCookies(response);
            LOGGER.info("POST /api/v1/auth/logout - Logout completed - Cookies deleted");
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            LOGGER.error("POST /api/v1/auth/logout - Error during logout - Error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }


}
