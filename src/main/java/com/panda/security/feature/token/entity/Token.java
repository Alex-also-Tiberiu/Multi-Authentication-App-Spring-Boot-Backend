package com.panda.security.feature.token.entity;

import com.panda.security.feature.user.entity.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Entity representing an authentication or security token.
 *
 * Each user can have multiple active tokens at the same time, one for each type:
 * - TokenType.BEARER: Access token for authenticating requests
 * - TokenType.REFRESH: Refresh token for obtaining new access tokens
 * - TokenType.CSRF: CSRF token for cross-site attack protection
 *
 * Tokens can be revoked or expired. Validation checks both flags in the database.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Token {

  @Id
  @GeneratedValue
  public Integer id;

  @Column(unique = true)
  public String token;

  @Enumerated(EnumType.STRING)
  public TokenType tokenType;

  public boolean revoked;

  @Column(nullable = false)
  public java.time.LocalDateTime expiresAt;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "user_id")
  public User user;
}
