package com.panda.security.core.auditing;

import com.panda.security.feature.user.entity.User;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

/**
 * ApplicationAuditAware provides the current auditor's ID for auditing purposes.
 * <p>
 * This class implements {@link AuditorAware} to supply the ID of the currently authenticated user.
 * It retrieves the {@link Authentication} from the {@link SecurityContextHolder} and checks if the user is authenticated.
 * If the user is authenticated and not anonymous, it returns the user's ID; otherwise, it returns an empty {@link Optional}.
 * <p>
 * This is typically used by Spring Data JPA to automatically populate audit fields such as createdBy and lastModifiedBy.
 */
public class ApplicationAuditAware implements AuditorAware<Integer> {

    @Override
    public Optional<Integer> getCurrentAuditor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken) {
            return Optional.empty();
        }

        User userPrincipal = (User) authentication.getPrincipal();
        return Optional.ofNullable(userPrincipal.getId());
    }
}

