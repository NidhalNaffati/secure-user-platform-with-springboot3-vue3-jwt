package com.nidhal.backend.config;

import com.nidhal.backend.filter.JwtAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

import static jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static org.springframework.security.config.Customizer.withDefaults;

/**
 * This class defines the security configuration for the application.
 * <p>
 * It enables web security and registers a JwtAuthenticationFilter and AuthenticationProvider.
 */
@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthorizationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;


    /**
     * Configures the security filter chain for the application.
     *
     * @param http the HttpSecurity object to configure
     * @return the SecurityFilterChain object
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // disable CSRF protection
            .csrf(AbstractHttpConfigurer::disable)

            // set up the headers to use the same origin
            .headers(headers -> headers.frameOptions(Customizer.withDefaults()))

            // set up the Exception Handler
            .exceptionHandling(exceptionHandling -> exceptionHandling.accessDeniedHandler((request, response, accessDeniedException) -> {
                response.setStatus(SC_FORBIDDEN);
                response.getWriter().write("access denied");
                log.error("Access denied error handler triggered");
            }))

            // set up the authorization rules
            .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                // allow access to the static resources to everyone
                .requestMatchers("/api/v1/auth/register/", "/api/v1/auth/refresh-token",
                    "/api/v1/auth/verify-user", "/api/v1/auth/authenticate",
                    "/api/v1/auth/forgot-password", "/api/v1/auth/reset-password",
                    // swagger endpoints
                    "/v2/api-docs", "/v3/api-docs", "/v3/api-docs/**",
                    "/swagger-resources", "/swagger-resources/**",
                    "/configuration/ui", "/configuration/security",
                    "/swagger-ui/**", "/webjars/**", "/swagger-ui.html"

                ).permitAll()

                // allow only authenticated user to this endpoint
                .requestMatchers("/api/v1/user/**").hasAuthority("ROLE_USER")

                // allow only authenticated admin to this endpoint
                .requestMatchers("/api/v1/admin/**").hasAuthority("ROLE_ADMIN")

                // any other request must be authenticated
                .anyRequest().authenticated())

            // set up the CORS configuration
            .cors(withDefaults()) // by default uses a Bean by the name of corsConfigurationSource

            // set up the session management
            .sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // set up the authentication provider
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)

            // set up the logout handler
            .logout(logout -> logout.logoutUrl("/api/v1/auth/logout")
                .addLogoutHandler(logoutHandler)
                .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext()));

        return http.build();
    }

    /**
     * Creates a CorsConfigurationSource bean that allows cross-origin resource sharing.
     *
     * @return the CorsConfigurationSource object
     */
    @Bean(name = "corsConfigurationSource")
    public CorsConfigurationSource corsConfiguration() {

        final CorsConfiguration corsConfiguration = new CorsConfiguration();

        corsConfiguration.setAllowedOriginPatterns(List.of("*"));

        corsConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));

        corsConfiguration.setAllowedHeaders(List.of(
            "Authorization", "Content-Type", "Access-Control-Allow-Origin",
            "Access-Control-Allow-Headers", "Access-Control-Expose-Headers")
        );

        corsConfiguration.setAllowCredentials(true);

        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", corsConfiguration);

        return source;
    }
}