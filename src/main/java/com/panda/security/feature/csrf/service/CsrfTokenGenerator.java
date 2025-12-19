package com.panda.security.feature.csrf.service;

import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Service to generate cryptographically secure CSRF tokens.
 */
@Service
public class CsrfTokenGenerator {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final int TOKEN_LENGTH = 32; // 32 bytes = 256 bits

    /**
     * Generates a new random CSRF token.
     * @return CSRF token in Base64 format
     */
    public String generateToken() {
        byte[] randomBytes = new byte[TOKEN_LENGTH];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}

