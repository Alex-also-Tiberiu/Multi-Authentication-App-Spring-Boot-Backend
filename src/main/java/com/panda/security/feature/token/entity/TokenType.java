package com.panda.security.feature.token.entity;

/**
 * Types of tokens managed by the application.
 * Each token type has a specific purpose and is saved as a separate record in the database:
 * - BEARER: JWT access token for authentication (15 minutes)
 * - CSRF: Token for Cross-Site Request Forgery protection (15 minutes)
 * - REFRESH: JWT refresh token for access token renewal (7 days)
 */
public enum TokenType {
  BEARER,   // JWT access token
  CSRF,     // CSRF protection token
  REFRESH   // JWT refresh token
}

