package com.panda.security.feature.token.repository;

import com.panda.security.feature.token.entity.Token;
import com.panda.security.feature.token.entity.TokenType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {

  @Query("""
            select t from Token t
             inner join User u
                on t.user.id = u.id
             where u.id = :id and t.revoked = false and t.expiresAt > :now
            """)
  List<Token> findAllValidTokenByUser(Integer id, LocalDateTime now);

  Optional<Token> findByToken(String token);

  @Query("""
            select t from Token t 
             inner join User u on t.user.id = u.id 
             where u.id = :userId and t.tokenType = :tokenType and t.revoked = false and t.expiresAt > :now
            """)
  Optional<Token> findValidTokenByUserAndType(Integer userId, TokenType tokenType, LocalDateTime now);

  void deleteByExpiresAtBeforeOrRevoked(LocalDateTime now, boolean revoked);
}

