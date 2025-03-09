package com.nidhal.backend.service;

import com.nidhal.backend.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.Key;
import java.util.Date;
import java.util.Map;

import static com.nidhal.backend.entity.Role.ROLE_USER;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    long refreshTokenExpirationTimeInMs = 604800000L;
    long accessTokenExpirationTimeInMs = 86400000L;
    long resetPasswordExpirationTimeInMs = 900000L;
    long enableAccountExpirationTimeInMs = 900000L;

    // Define an acceptable margin of error ( this is needed because of the time it takes create the token )
    long marginOfError = 2000;

    @Mock
    private UserDetails userDetails;

    @InjectMocks
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        String secretKey = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
        ReflectionTestUtils.setField(jwtService, "refreshTokenExpirationTimeInMs", refreshTokenExpirationTimeInMs);
        ReflectionTestUtils.setField(jwtService, "accessTokenExpirationTimeInMs", accessTokenExpirationTimeInMs);
        ReflectionTestUtils.setField(jwtService, "resetPasswordExpirationTimeInMs", resetPasswordExpirationTimeInMs);
        ReflectionTestUtils.setField(jwtService, "enableAccountExpirationTimeInMs", enableAccountExpirationTimeInMs);
        ReflectionTestUtils.setField(jwtService, "SECRET_KEY", secretKey);
    }

    private String generateToken(String username, long expirationTimeInMs) {
        Date issuedAt = new Date(System.currentTimeMillis());
        Date expirationDate = new Date(System.currentTimeMillis() + expirationTimeInMs);

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(issuedAt)
                .setExpiration(expirationDate)
                .signWith(jwtService.getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    @Test
    void extractClaim_ShouldReturnExpectedClaimValue() {
        // Given
        String token = generateToken("testuser", 3600000L);
        Claims claims = Jwts.parserBuilder().setSigningKey(jwtService.getSignInKey()).build().parseClaimsJws(token).getBody();

        // When
        String subject = jwtService.extractClaim(token, Claims::getSubject);

        // Then
        assertEquals(claims.getSubject(), subject);
    }

    @Test
    void extractUsername_ShouldReturnExpectedUsername() {
        // Given
        String token = generateToken("testuser", 3600000L);
        Claims claims = Jwts.parserBuilder().setSigningKey(jwtService.getSignInKey()).build().parseClaimsJws(token).getBody();

        // When
        String username = jwtService.extractUsername(token);

        // Then
        assertEquals(claims.getSubject(), username);
    }

    @Test
    void extractExpiration_ShouldReturnExpectedExpirationDate() {
        // Given
        String token = generateToken("testuser", 3600000L);
        Claims claims = Jwts.parserBuilder().setSigningKey(jwtService.getSignInKey()).build().parseClaimsJws(token).getBody();

        // When
        Date expiration = jwtService.extractExpiration(token);

        // Then
        assertEquals(claims.getExpiration(), expiration);
    }

    @Test
    void getUserClaims_ShouldReturnExpectedUserClaims() {
        // Given
        User user = new User();
        user.setRole(ROLE_USER);
        user.setEnabled(true);

        // When
        Map<String, Object> claims = jwtService.getUserClaims(user);

        // Then
        assertEquals(ROLE_USER, claims.get("role"));
        assertTrue((Boolean) claims.get("enabled"));
    }

    @Test
    void generateRefreshToken_ShouldReturnTokenWithExpectedExpiration() {
        // Given
        String username = "testuser";
        long expectedExpirationTime = refreshTokenExpirationTimeInMs;

        // When
        String refreshToken = jwtService.generateRefreshToken(username);
        Date expiration = jwtService.extractExpiration(refreshToken);
        long actualExpirationTime = expiration.getTime() - System.currentTimeMillis();

        // Then
        assertTrue(Math.abs(expectedExpirationTime - actualExpirationTime) <= marginOfError);
    }

    @Test
    void generateTokenForEnableAccount_ShouldReturnTokenWithExpectedExpiration() {
        // Given
        String username = "testuser";
        long expectedExpirationTime = enableAccountExpirationTimeInMs;

        // When
        String token = jwtService.generateTokenForEnableAccount(username);
        Date expiration = jwtService.extractExpiration(token);
        long actualExpirationTime = expiration.getTime() - System.currentTimeMillis();

        // Then
        assertTrue(Math.abs(expectedExpirationTime - actualExpirationTime) <= marginOfError);
    }

    @Test
    void generateTokenForResetPassword_ShouldReturnTokenWithExpectedExpiration() {
        // Given
        String username = "testuser";
        long expectedExpirationTime = resetPasswordExpirationTimeInMs;

        // When
        String token = jwtService.generateTokenForResetPassword(username);
        Date expiration = jwtService.extractExpiration(token);
        long actualExpirationTime = expiration.getTime() - System.currentTimeMillis();

        // Then
        assertTrue(Math.abs(expectedExpirationTime - actualExpirationTime) <= marginOfError);

    }

    @Test
    void generateAccessToken_ShouldReturnTokenWithExpectedExpirationAndClaims() {
        // Given
        User user = new User();
        user.setEmail("testuser@example.com");
        user.setRole(ROLE_USER);
        user.setEnabled(true);

        long expectedExpirationTime = accessTokenExpirationTimeInMs;

        // When
        String token = jwtService.generateAccessToken(user);
        Date expiration = jwtService.extractExpiration(token);
        long actualExpirationTime = expiration.getTime() - System.currentTimeMillis();
        Claims claims = jwtService.extractAllClaims(token);

        // Then
        assertTrue(Math.abs(expectedExpirationTime - actualExpirationTime) <= marginOfError);
        assertEquals(user.getEmail(), jwtService.extractUsername(token));
        assertEquals("ROLE_USER", claims.get("role"));
        assertTrue(claims.get("enabled", Boolean.class));
    }

    @Test
    void isTokenValid_ShouldReturnTrueForValidToken() {
        // Given
        String username = "testuser";
        String token = generateToken(username, 3600000L);
        when(userDetails.getUsername()).thenReturn(username);

        // When
        boolean isValid = jwtService.isTokenValid(token, userDetails);

        // Then
        assertTrue(isValid);
    }

    @Test
    void isTokenValid_ShouldReturnFalseForInvalidUsername() {
        // Given
        String token = generateToken("testuser", 3600000L);
        when(userDetails.getUsername()).thenReturn("anotheruser");

        // When
        boolean isValid = jwtService.isTokenValid(token, userDetails);

        // Then
        assertFalse(isValid);
    }

    @Test
    void isTokenExpired_ShouldThrowExpiredJwtExceptionForExpiredToken() {
        // Given
        String token = generateToken("testuser", -3600000L);

        // When/Then
        assertThrows(ExpiredJwtException.class, () -> jwtService.isTokenExpired(token));
    }

    @Test
    void isTokenExpired_ShouldReturnFalseForValidToken() {
        // Given
        String token = generateToken("testuser", 3600000L);

        // When
        boolean isExpired = jwtService.isTokenExpired(token);

        // Then
        assertFalse(isExpired);
    }

    @Test
    void extractAllClaims_ShouldReturnExpectedClaims() {
        // Given
        String token = generateToken("testuser", 3600000L);

        // When
        Claims claims = jwtService.extractAllClaims(token);

        // Then
        assertEquals("testuser", claims.getSubject());
        assertFalse(claims.isEmpty());
    }

    @Test
    void getSignInKey_ShouldReturnValidKey() {
        // When
        Key signInKey = jwtService.getSignInKey();

        // Then
        assertNotNull(signInKey);
    }
}