package com.panda.security.feature.csrf.service;

import com.panda.security.feature.token.entity.Token;
import com.panda.security.feature.token.entity.TokenType;
import com.panda.security.feature.token.repository.TokenRepository;
import com.panda.security.feature.user.entity.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

/**
 * Service for managing CSRF tokens associated with users.
 * Uses TokenType.CSRF to distinguish CSRF tokens from JWT tokens.
 */
@Service
@RequiredArgsConstructor
public class CsrfTokenService {

    private final TokenRepository tokenRepository;
    private final CsrfTokenGenerator csrfTokenGenerator;

    /**
     * Generates a new CSRF token, saves it as a separate record in the database,
     * and sets it as a cookie in the response.
     *
     * @param user     the user for whom to generate the token
     * @param response the HTTP response to set the cookie
     */
    public void generateAndSaveCsrfToken( User user, HttpServletResponse response) {
        // Generate the CSRF token
        String csrfToken = csrfTokenGenerator.generateToken();

        // Revoke any previous CSRF tokens for the user
        revokeAllUserCsrfTokens(user);

        // Save the new CSRF token as a separate record
        Token token = Token.builder()
                .user(user)
                .token(csrfToken)
                .tokenType(TokenType.CSRF)
                .revoked(false)
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .build();
        tokenRepository.save(token);

        // Set the CSRF cookie
        setCsrfCookie(response, csrfToken);
    }

    /**
     * Validates the CSRF token from the request by comparing it with the one saved in the database.
     *
     * @param request the HTTP request
     * @param user the authenticated user
     * @return true if the CSRF token is valid, false otherwise
     */
    public boolean validateCsrfToken(HttpServletRequest request, User user) {
        // Get the CSRF token from the header
        String csrfTokenFromHeader = request.getHeader("X-XSRF-TOKEN");

        if (csrfTokenFromHeader == null || csrfTokenFromHeader.isEmpty()) {
            return false;
        }

        // Find the valid CSRF token for the user in the database
        return tokenRepository.findValidTokenByUserAndType(user.getId(), TokenType.CSRF, LocalDateTime.now())
            .map(token -> csrfTokenFromHeader.equals(token.getToken()))
            .orElse(false);
    }

    /**
     * Revoke all CSRF tokens for the user.
     *
     * @param user the user
     */
    private void revokeAllUserCsrfTokens(User user) {
        tokenRepository.findValidTokenByUserAndType(user.getId(), TokenType.CSRF, LocalDateTime.now())
            .ifPresent(token -> {
                token.setRevoked(true);
                tokenRepository.save(token);
            });
    }

    /**
     * Revoke the user's CSRF tokens and remove the cookie.
     *
     * @param user the user
     * @param response the HTTP response
     */
    public void revokeCsrfToken(User user, HttpServletResponse response) {
        revokeAllUserCsrfTokens(user);
        clearCsrfCookie(response);
    }

    /**
     * Sets the CSRF cookie in the response.
     *
     * @param response the HTTP response
     * @param csrfToken the CSRF token
     */
    private void setCsrfCookie(HttpServletResponse response, String csrfToken) {
        ResponseCookie cookie = ResponseCookie
                .from("XSRF-TOKEN", csrfToken)
                .path("/")
                .maxAge(15 * 60) // 15 minutes, same as access token
                .httpOnly(false) // Must be readable by JavaScript
                .secure(false) // true in production with HTTPS
                .sameSite("Strict")
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    /**
     * Removes the CSRF cookie.
     *
     * @param response the HTTP response
     */
    public void clearCsrfCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie
                .from("XSRF-TOKEN", "")
                .path("/")
                .maxAge(0) // Expire immediately
                .httpOnly(false)
                .secure(false)
                .sameSite("Strict")
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    /**
     * Gets the CSRF token from the database for the user.
     *
     * @param user the user
     * @return the CSRF token or null if not found
     */
    public String getCsrfTokenForUser(User user) {
        return tokenRepository.findValidTokenByUserAndType(user.getId(), TokenType.CSRF, LocalDateTime.now())
                .map(Token::getToken)
                .orElse(null);
    }
}

