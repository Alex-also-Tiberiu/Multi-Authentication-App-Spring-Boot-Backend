package com.panda.security.infrastructure.scheduler;

import com.panda.security.feature.token.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class TokenCleanupScheduler {

    private TokenRepository tokenRepository;

    @Scheduled(cron = "0 0 * * * *")  // Ogni ora
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        tokenRepository.deleteByExpiresAtBeforeOrRevoked(now, true);
    }

}

