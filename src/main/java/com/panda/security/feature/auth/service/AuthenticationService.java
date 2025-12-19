package com.panda.security.feature.auth.service;

import com.panda.security.config.JwtService;
import com.panda.security.feature.auth.dto.AuthenticationResponse;
import com.panda.security.feature.auth.dto.RegisterRequest;
import com.panda.security.feature.csrf.service.CsrfTokenService;
import com.panda.security.feature.token.entity.Token;
import com.panda.security.feature.token.entity.TokenType;
import com.panda.security.feature.token.repository.TokenRepository;
import com.panda.security.feature.user.entity.User;
import com.panda.security.feature.user.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

/**
 * Service that handles authentication, token generation, and session management.
 *
 * Manages three types of tokens saved in the database:
 * - TokenType.BEARER: JWT access token (15 minutes)
 * - TokenType.REFRESH: JWT refresh token (7 days) with rotation
 * - TokenType.CSRF: CSRF protection token (15 minutes)
 *
 * All tokens are saved in the database to allow immediate revocation.
 */
@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final CsrfTokenService csrfTokenService;

    public AuthenticationResponse register( RegisterRequest request ) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        var savedUser = repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    /**
     * Authenticates the user and sets the necessary authentication cookies.
     *
     * Process:
     * 1. Validates user credentials
     * 2. Generates access token (JWT) and refresh token (JWT)
     * 3. Revokes all previous tokens for the user
     * 4. Saves access token (BEARER) and refresh token (REFRESH) in the database
     * 5. Sets HttpOnly cookies for access_token and refresh_token
     * 6. Generates and saves CSRF token (TokenType.CSRF) in the database
     * 7. Sets XSRF-TOKEN cookie (readable by JavaScript)
     *
     * @param authentication the Authentication object with user credentials
     * @param response the HttpServletResponse to set cookies
     */
    public void authenticateAndSetCookies(Authentication authentication, HttpServletResponse response) {
        var user = repository.findByEmail(authentication.getName())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);

        setAuthenticationCookies(response, jwtToken, refreshToken);

        // Genera e salva il token CSRF associato all'utente (record separato con TokenType.CSRF)
        csrfTokenService.generateAndSaveCsrfToken(user, response);
    }

    /**
     * Sets the authentication cookies (access_token and refresh_token).
     * Uses Spring's ResponseCookie to ensure correct SameSite support.
     *
     * @param response the HttpServletResponse
     * @param accessToken the JWT access token
     * @param refreshToken the JWT refresh token
     */
    private void setAuthenticationCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        // Cookie per access token
        ResponseCookie accessCookie = ResponseCookie
                .from("access_token", accessToken)
                .httpOnly(true)
                .secure(false) // true in produzione con HTTPS
                .path("/")
                .maxAge(15 * 60) // 15 minuti
                .sameSite("Strict")
                .build();
        response.addHeader("Set-Cookie", accessCookie.toString());

        // Cookie per refresh token
        ResponseCookie refreshCookie = ResponseCookie
                .from("refresh_token", refreshToken)
                .httpOnly(true)
                .secure(false) // true in produzione con HTTPS
                .path("/api/v1/auth/refresh-token")
                .maxAge(7 * 24 * 60 * 60) // 7 giorni
                .sameSite("Strict")
                .build();
        response.addHeader("Set-Cookie", refreshCookie.toString());
    }

    /**
     * Saves the JWT access token in the database with TokenType.BEARER.
     *
     * @param user the token owner
     * @param jwtToken the JWT token to save
     */
    private void saveUserToken( User user, String jwtToken ) {
        var expirationDate = jwtService.getExpirationDateFromToken(jwtToken);
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expiresAt(expirationDate.toInstant().atZone(java.time.ZoneId.systemDefault()).toLocalDateTime())
                .build();
        tokenRepository.save(token);
    }

    /**
     * Saves the JWT refresh token in the database with TokenType.REFRESH.
     * This allows validation and revocation of refresh tokens.
     *
     * @param user the token owner
     * @param refreshToken the JWT refresh token to save
     */
    private void saveRefreshToken( User user, String refreshToken ) {
        var expirationDate = jwtService.getExpirationDateFromToken(refreshToken);
        var token = Token.builder()
                .user(user)
                .token(refreshToken)
                .tokenType(TokenType.REFRESH)
                .revoked(false)
                .expiresAt(expirationDate.toInstant().atZone(java.time.ZoneId.systemDefault()).toLocalDateTime())
                .build();
        tokenRepository.save(token);
    }

    /**
     * Revokes all tokens for the user (BEARER, REFRESH, CSRF).
     * This method is called:
     * - On login (to invalidate previous sessions)
     * - On refresh token (to implement token rotation)
     *
     * @param user the user whose tokens to revoke
     */
    private void revokeAllUserTokens( User user ) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId(), java.time.LocalDateTime.now());
        if(validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    /**
     * Renews the access token using the refresh token.
     *
     * Implements Refresh Token Rotation for enhanced security:
     * 1. Validates the refresh token from the cookie
     * 2. Checks that the refresh token exists in the database (TokenType.REFRESH)
     * 3. Generates NEW access token, NEW refresh token, and NEW CSRF token
     * 4. Revokes ALL old tokens (BEARER, REFRESH, CSRF)
     * 5. Saves the new tokens in the database
     * 6. Sets the new cookies
     *
     * This prevents reuse of stolen refresh tokens.
     *
     * @param request the HttpServletRequest containing the refresh token cookie
     * @param response the HttpServletResponse to set the new cookies
     * @throws IOException if an I/O error occurs
     */
    public void refreshToken( HttpServletRequest request, HttpServletResponse response ) throws IOException {
        final String refreshToken = getRefreshTokenFromCookie(request);
        final String userEmail;

        if(refreshToken == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing refresh token");
            return;
        }

        userEmail = jwtService.extractUsername(refreshToken);
        if(userEmail != null) {
            var user = this.repository.findByEmail(userEmail)
                    .orElseThrow();

            // Verifica che il refresh token sia valido nel JWT E nel database
            var isRefreshTokenValid = tokenRepository.findByToken(refreshToken)
                    .map(t -> t.getTokenType() == TokenType.REFRESH && !t.isRevoked())
                    .orElse(false);

            if(jwtService.isTokenValid(refreshToken, user) && isRefreshTokenValid) {
                var accessToken = jwtService.generateToken(user);
                var newRefreshToken = jwtService.generateRefreshToken(user); // Genera NUOVO refresh token

                revokeAllUserTokens(user); // Revoca tutti i token (BEARER, CSRF, REFRESH)
                saveUserToken(user, accessToken);
                saveRefreshToken(user, newRefreshToken); // Salva nuovo refresh token
                setAuthenticationCookies(response, accessToken, newRefreshToken);

                // Rigenera il token CSRF per l'utente
                csrfTokenService.generateAndSaveCsrfToken(user, response);
            } else {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid refresh token");
            }
        } else {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid refresh token");
        }
    }

    private String getRefreshTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refresh_token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    /**
     * Removes all authentication cookies (access_token, refresh_token, XSRF-TOKEN).
     * Called during logout to clean up the client session.
     *
     * @param response the HttpServletResponse
     */
    public void cleanCookies( HttpServletResponse response ) {
        // Delete the cookie access_token
        ResponseCookie accessCookie = ResponseCookie
                .from("access_token", "")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(0) // Expire immediately
                .sameSite("Strict")
                .build();
        response.addHeader("Set-Cookie", accessCookie.toString());

        // Delete il cookie refresh_token
        ResponseCookie refreshCookie = ResponseCookie
                .from("refresh_token", "")
                .httpOnly(true)
                .secure(false)
                .path("/api/v1/auth/refresh-token")
                .maxAge(0) // Expire immediately
                .sameSite("Strict")
                .build();
        response.addHeader("Set-Cookie", refreshCookie.toString());

        // Delete il cookie CSRF
        csrfTokenService.clearCsrfCookie(response);
    }
}

