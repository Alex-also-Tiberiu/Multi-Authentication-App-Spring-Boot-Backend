package com.panda.security.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
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

    @PostMapping(value = "/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
        LOGGER.info("POST /api/v1/auth/register (form) - Richiesta registrazione per email: {}", request.getEmail());
        try {
            AuthenticationResponse response = service.register(request);
            LOGGER.info("POST /api/v1/auth/register (form) - Registrazione completata con successo per email: {}", request.getEmail());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            LOGGER.error("POST /api/v1/auth/register (form) - Errore durante registrazione per email: {} - Errore: {}", request.getEmail(), e.getMessage(), e);
            throw e;
        }
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            LOGGER.warn("POST /api/v1/auth/authenticate - User not authorized");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String email = authentication.getName();
        try {
            AuthenticationResponse response = service.authenticate(authentication);
            LOGGER.debug("POST /api/v1/auth/authenticate - Autenticazione completata con successo per {}", email);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            LOGGER.error("POST /api/v1/auth/authenticate - {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken( HttpServletRequest request, HttpServletResponse response ) throws IOException {
        LOGGER.info("POST /api/v1/auth/refresh-token - Richiesta refresh token");
        try {
            service.refreshToken(request, response);
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (IOException ex) {
            LOGGER.error("POST /api/v1/auth/refresh-token - Errore durante il refresh token - Errore: {}", ex.getMessage(), ex);
            return new ResponseEntity<>(HttpStatus.CONFLICT);
        }
    }


}
