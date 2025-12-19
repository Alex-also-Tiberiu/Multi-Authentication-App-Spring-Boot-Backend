package com.panda.security.config.security.filters;

import com.panda.security.feature.user.entity.User;
import com.panda.security.feature.csrf.service.CsrfTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * Filter that validates the CSRF token for data-modifying requests.
 * The CSRF token is compared with the one saved in the database (TokenType.CSRF) for the authenticated user.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CsrfCookieFilter extends OncePerRequestFilter {

    private final CsrfTokenService csrfTokenService;

    // Endpoints that do not require CSRF validation
    private static final List<String> CSRF_EXEMPT_ENDPOINTS = Arrays.asList(
        "/api/v1/auth/register",
        "/api/v1/auth/refresh-token",
        "/api/v1/auth/authenticate",
        "/api/v1/csrf/token",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger-ui",
        "/swagger-resources",
        "/configuration",
        "/webjars",
        "/error"
    );

    // HTTP methods that require CSRF validation
    private static final List<String> CSRF_REQUIRED_METHODS = Arrays.asList(
        "POST", "PUT", "DELETE", "PATCH"
    );

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {

        String requestPath = request.getRequestURI();
        String requestMethod = request.getMethod();

        log.debug("CSRF Filter - Path: {}, Method: {}", requestPath, requestMethod);

        // If the endpoint is exempt from CSRF validation, continue
        if (isExemptEndpoint(requestPath)) {
            log.debug("CSRF Filter - Endpoint {} is exempt", requestPath);
            filterChain.doFilter(request, response);
            return;
        }

        // If the HTTP method does not require CSRF (GET, HEAD, OPTIONS), continue
        if (!CSRF_REQUIRED_METHODS.contains(requestMethod)) {
            log.debug("CSRF Filter - Method {} does not require CSRF", requestMethod);
            filterChain.doFilter(request, response);
            return;
        }

        // Get the authenticated user from the SecurityContext
        var authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated() ||
            !(authentication.getPrincipal() instanceof User)) {
            log.debug("CSRF Filter - No authenticated user, skipping CSRF check");
            // If there is no authenticated user, let other filters handle the request
            filterChain.doFilter(request, response);
            return;
        }

        User user = (User) authentication.getPrincipal();

        // Validate the CSRF token
        boolean isValidCsrf = csrfTokenService.validateCsrfToken(request, user);

        if (!isValidCsrf) {
            log.warn("CSRF Filter - Invalid CSRF token for user {} on path {}", user.getEmail(), requestPath);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Invalid CSRF token\"}");
            return;
        }

        log.debug("CSRF Filter - Valid CSRF token for user {}", user.getEmail());
        // CSRF token is valid, continue with the request
        filterChain.doFilter(request, response);
    }

    /**
     * Check if the endpoint is exempt from CSRF validation
     */
    private boolean isExemptEndpoint(String requestPath) {
        return CSRF_EXEMPT_ENDPOINTS.stream()
                .anyMatch(requestPath::startsWith);
    }
}

