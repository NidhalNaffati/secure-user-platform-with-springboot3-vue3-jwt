package com.nidhal.backend.filter;

import com.nidhal.backend.entity.UserDetailsImpl;
import com.nidhal.backend.service.JwtService;
import com.nidhal.backend.service.TokenService;
import com.nidhal.backend.service.UserService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Enumeration;
import java.util.List;

import static jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

/**
 * This class is a Spring component that extends OncePerRequestFilter, which is a convenient base class for filter
 * implementations. It filters incoming requests and checks for a valid JWT in the Authorization header.
 * If a valid JWT is found, it authenticates the user associated with the token.
 * If the token is absent or not valid, the request is rejected.
 * <p>
 * The component has three dependencies: JwtService, UserService, and TokenService.
 */
@Component
@Slf4j
@AllArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserService userService;
    private final TokenService tokenService;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    // The Authorization header is in the form of Bearer <token>. The prefix Bearer is removed to extract the token.
    private static final String AUTHORIZATION_HEADER = "Authorization";

    // The prefix Bearer is removed to extract the token.
    private static final String BEARER_PREFIX = "Bearer ";

    // The list of public endpoints that do not require authentication
    private static final List<String> PUBLIC_ENDPOINTS = List.of(
        "/api/v1/auth/register",
        "/api/v1/auth/refresh-token",
        "/api/v1/auth/verify-user",
        "/api/v1/auth/authenticate",
        "/api/v1/auth/forgot-password",
        "/api/v1/auth/reset-password",

        // Swagger endpoints
        "/v2/api-docs", "/v3/api-docs", "/v3/api-docs/**",
        "/swagger-resources", "/swagger-resources/**",
        "/configuration/ui", "/configuration/security",
        "/swagger-ui/**", "/webjars/**", "/swagger-ui.html"
    );

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        // Check if the request is for a public endpoint
        if (isPublicEndpoint(request)) {
            // If the request is for a public endpoint, skip the filter
            log.info("Skipping the filter for the following request URL {}", request.getServletPath());
            filterChain.doFilter(request, response);
            return;
        }

        log.info("Request URL: {}", request.getServletPath());
        log.info("Request Method: {}", request.getMethod());
        log.info("Request Headers:");
        // print the token and extract all the data from the request
        Enumeration<String> headerNames = request.getHeaderNames();
        // print the headers
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            log.info("Header Name: {}", headerName);
            log.info("Header Value: {}", request.getHeader(headerName));
        }

        // Check if the Authorization header is missing or does not contain a valid JWT
        String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            handleMissingToken(response, request);
            return;
        }

        // Extract username from the JWT
        String jwt = authHeader.substring(7);
        // print the token and extract all the data from the request
        String username = extractUsernameFromJwt(jwt);

        // If username is null, it indicates an issue with the JWT.
        if (username == null) {
            handleInvalidToken(response);
            return;
        }

        // If the user is already authenticated, no need to process further
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        // Load UserDetails from the database using the extracted username
        UserDetailsImpl userDetails = userService.loadUserByUsername(username);

        // Check if the JWT is valid and if the token is valid
        if (!isTokenValid(jwt, userDetails)) {
            // Handle the case where the JWT is not valid
            handleInvalidToken(response);
            return;
        }

        // Create a new authentication token with the retrieved user
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
            userDetails,
            null,
            userDetails.getAuthorities()
        );
        // Set the details of the authentication token
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        // Set the authentication token in the SecurityContextHolder
        SecurityContextHolder.getContext().setAuthentication(authToken);

        // Proceed with the filter chain
        filterChain.doFilter(request, response);
    }

    private boolean isPublicEndpoint(HttpServletRequest request) {
        String path = request.getServletPath();
        return PUBLIC_ENDPOINTS.stream().anyMatch(pattern -> pathMatcher.match(pattern, path));
    }

    private boolean isTokenValid(String jwt, UserDetailsImpl userDetails) {
        return tokenService.isTokenValid(jwt) && jwtService.isTokenValid(jwt, userDetails);
    }

    private void handleMissingToken(HttpServletResponse response, HttpServletRequest request) throws IOException {
        log.error("Authorization header is missing or does not contain a valid JWT for the following URL: {}", request.getServletPath());
        response.sendError(SC_UNAUTHORIZED, "Authorization header is missing or does not contain a valid JWT");
    }

    private void handleInvalidToken(HttpServletResponse response) throws IOException {
        log.warn("JWT is not valid");
        response.setStatus(SC_UNAUTHORIZED);
        response.getWriter().write("JWT is not valid");
    }

    private String extractUsernameFromJwt(String jwt) {
        try {
            return jwtService.extractUsername(jwt);
        } catch (ExpiredJwtException ex) {
            log.warn("JWT has expired: {}", ex.getMessage());
            return null;
        } catch (MalformedJwtException ex) {
            log.warn("JWT is malformed: {}", ex.getMessage());
            return null;
        } catch (SignatureException ex) {
            log.warn("JWT signature is invalid: {}", ex.getMessage());
            return null;
        } catch (UnsupportedJwtException ex) {
            log.warn("JWT is unsupported: {}", ex.getMessage());
            return null;
        }
    }
}
