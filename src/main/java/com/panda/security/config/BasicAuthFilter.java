package com.panda.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
@RequiredArgsConstructor
public class BasicAuthFilter extends OncePerRequestFilter {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        if ("/api/v1/auth/authenticate".equals(request.getServletPath())) {
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Basic ")) {
                try {
                    String base64Credentials = authHeader.substring("Basic ".length());
                    byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
                    String credentials = new String(credDecoded, StandardCharsets.UTF_8);
                    final String[] values = credentials.split(":", 2);
                    String username = values[0];
                    String password = values[1];

                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                    if(ObjectUtils.isEmpty(userDetails) || !passwordEncoder.matches(password, userDetails.getPassword())) {
                        throw new RuntimeException("User doesn't exist or wrong credentials");
                    }

                    Authentication auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(auth);
                } catch (Exception e) {
                    response.setHeader("WWW-Authenticate", "Basic realm=\"Realm\"");
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Basic Authentication");
                    return;
                }
            } else {
                response.setHeader("WWW-Authenticate", "Basic realm=\"Realm\"");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing Basic Authentication");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}

