package com.nidhal.backend.service;

import com.nidhal.backend.entity.User;
import com.nidhal.backend.exception.EmailAlreadyExistsException;
import com.nidhal.backend.exception.PasswordDontMatchException;
import com.nidhal.backend.entity.Role;
import com.nidhal.backend.entity.UserDetailsImpl;
import com.nidhal.backend.requests.AuthenticationRequest;
import com.nidhal.backend.requests.AuthenticationResponse;
import com.nidhal.backend.requests.RegisterRequest;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.MailSendException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;

import java.io.PrintWriter;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthenticationServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private UserService userService;
    @Mock
    private EmailService emailService;
    @Mock
    private JwtService jwtService;
    @Mock
    private TokenService tokenService;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private PrintWriter printWriter;
    @InjectMocks
    private AuthenticationService underTestAuthenticationService;

    private static final User USER = new User();

    static {
        USER.setId(1L);
        USER.setEmail("test@example.com");
        USER.setPassword("password");
    }

    private static final RegisterRequest USER_REGISTER_REQUEST =
            new RegisterRequest(
                    "john",
                    "doe",
                    "john@example.com",
                    "password",
                    "password",
                    Role.ROLE_USER
            );


    @Test
    public void authenticate_ValidCredentials_ReturnsAuthenticationResponse() {
        // given
        AuthenticationRequest request = new AuthenticationRequest("test@example.com", "password");

        when(userService.validateCredentials(request.email(), request.password())).thenReturn(USER);
        when(jwtService.generateAccessToken(USER)).thenReturn("accessToken");
        when(jwtService.generateRefreshToken(USER.getEmail())).thenReturn("refreshToken");

        // when
        AuthenticationResponse response = underTestAuthenticationService.authenticate(request);

        // then
        assertNotNull(response);
        assertEquals("accessToken", response.accessToken());
        assertEquals("refreshToken", response.refreshToken());
        verify(authenticationManager).authenticate(any()); // Verify that the authenticationManager.authenticate method was called
        verify(userService).validateCredentials(request.email(), request.password()); // Verify that the userService.validateCredentials method was called
        verify(jwtService).generateAccessToken(USER); // Verify that the jwtService.generateAccessToken method was called
        verify(jwtService).generateRefreshToken(USER.getEmail()); // Verify that the jwtService.generateRefreshToken method was called
    }

    @Test
    public void authenticate_InvalidCredentials_ThrowsBadCredentialsException() {
        // given
        AuthenticationRequest request = new AuthenticationRequest("test@example.com", "invalidPassword");

        // when
        when(userService.validateCredentials(request.email(), request.password()))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        // then
        assertThrows(BadCredentialsException.class, () -> underTestAuthenticationService.authenticate(request));
    }

    @Test
    void registerNewUer_ShouldSuccess() {
        // given
        RegisterRequest registerRequest = USER_REGISTER_REQUEST;

        User user = USER_REGISTER_REQUEST.toUser();

        String jwtToken = "dummyJwtToken";

        when(userService.emailExists(registerRequest.email())).thenReturn(false);
        when(userService.saveUser(any(User.class))).thenReturn(user);
        when(jwtService.generateTokenForEnableAccount(registerRequest.email())).thenReturn(jwtToken);

        // when
        underTestAuthenticationService.registerUser(registerRequest);

        // then
        // assertEquals(jwtToken, result);
        verify(tokenService).saveUserToken(user, jwtToken);
        verify(emailService).sendActivationLink(eq(registerRequest.email()), anyString(), anyString());
    }

    @Test
    public void registerNewUser_WithMismatchedPasswords_ShouldThrowPasswordDontMatchException() {
        // given
        RegisterRequest registerRequest =
                new RegisterRequest(
                        "john",
                        "doe",
                        "john@example.com",
                        "password_11111111",
                        "password_22222222",
                        Role.ROLE_USER
                );

        // when/then
        assertThrows(PasswordDontMatchException.class, () -> underTestAuthenticationService.registerUser(registerRequest));

    }

    @Test
    public void registerNewUser_WithExistingEmail_ShouldThrowEmailAlreadyExistsException() {
        // given
        RegisterRequest registerRequest = USER_REGISTER_REQUEST;

        when(userService.emailExists(registerRequest.email())).thenReturn(true);

        // when/then
        assertThrows(EmailAlreadyExistsException.class, () -> underTestAuthenticationService.registerUser(registerRequest));
    }

    @Test
    public void registerNewUser_ShouldSaveUserAndSendActivationEmail() {
        // given
        RegisterRequest registerRequest = USER_REGISTER_REQUEST;

        User user = USER_REGISTER_REQUEST.toUser();

        String jwtToken = "dummyJwtToken";
        String activationLink = "http://localhost:9090/api/v1/auth/enable-user/" + jwtToken;

        when(userService.emailExists(registerRequest.email())).thenReturn(false);
        when(userService.saveUser(any(User.class))).thenReturn(user);
        when(jwtService.generateTokenForEnableAccount(registerRequest.email())).thenReturn(jwtToken);

        // when
        underTestAuthenticationService.registerUser(registerRequest);

        // then
        //  assertEquals(jwtToken, result);
        verify(tokenService).saveUserToken(user, jwtToken);
        verify(emailService).sendActivationLink(registerRequest.email(), registerRequest.firstName(), activationLink);
        verifyNoMoreInteractions(emailService);
    }

    @Test
    public void registerNewUser_ShouldThrowMailSendException_WhenEmailServiceFails() {
        // given
        RegisterRequest registerRequest = USER_REGISTER_REQUEST;
        User user = USER_REGISTER_REQUEST.toUser();

        String jwtToken = "dummyJwtToken";

        when(userService.emailExists(anyString())).thenReturn(false);
        when(userService.saveUser(any(User.class))).thenReturn(user);
        when(jwtService.generateTokenForEnableAccount(anyString())).thenReturn(jwtToken);

        doThrow(new MailSendException(registerRequest.email()))
                .when(emailService).sendActivationLink(anyString(), anyString(), anyString());

        // when
        assertThrows(MailSendException.class, () -> underTestAuthenticationService.registerUser(registerRequest));

        // then
        verify(emailService).sendActivationLink(anyString(), anyString(), anyString());
    }

    @Test
    void sendResetPasswordRequestToUser_shouldSendResetPasswordLink() {
        // given
        User user = USER_REGISTER_REQUEST.toUser();

        // Mock the UserService to return a user
        when(userService.findUserByEmail(user.getEmail())).thenReturn(user);

        // Mock the JwtService to return a fixed token
        when(jwtService.generateTokenForResetPassword(user.getEmail())).thenReturn("jwt-token");

        // when
        // Invoke the method
        underTestAuthenticationService.sendResetPasswordRequestToUser(user.getEmail());

        // then
        // Verify that UserService.findUserByEmail was called with the correct email
        verify(userService).findUserByEmail(user.getEmail());

        // Verify that JwtService.generateTokenForResetPassword was called with the correct email
        verify(jwtService).generateTokenForResetPassword(user.getEmail());

        // Verify that EmailService.sendResetPasswordRequestToUser was called with the correct parameters
        verify(emailService).sendResetPasswordRequestToUser(
                eq(user.getEmail()),
                eq(user.getFirstName()),
                eq("http://localhost:5173/reset-password?token=jwt-token")
        );
    }

    @Test
    void sendResetPasswordRequestToUser_shouldThrowEmailServiceException() {
        // given
        User user = USER_REGISTER_REQUEST.toUser();

        when(userService.findUserByEmail(user.getEmail())).thenReturn(user);

        // Mock the JwtService to return a fixed token
        when(jwtService.generateTokenForResetPassword(user.getEmail())).thenReturn("jwt-token");

        // Mock the EmailService to throw an exception
        doThrow(new MailSendException("Error sending email")).when(emailService)
                .sendResetPasswordRequestToUser(
                        eq("john@example.com"),
                        eq("John"),
                        eq("http://localhost:5173/reset-password?token=jwt-token")
                );

        // when/then
        // Invoke the method and expect it to throw a MailSendException
        assertThrows(MailSendException.class, () -> underTestAuthenticationService.sendResetPasswordRequestToUser("john@example.com"));

        // Verify that UserService.findUserByEmail was called with the correct email
        verify(userService).findUserByEmail(user.getEmail());

        // Verify that JwtService.generateTokenForResetPassword was called with the correct email
        verify(jwtService).generateTokenForResetPassword(user.getEmail());

        // Verify that EmailService.sendResetPasswordRequestToUser was called with the correct parameters
        verify(emailService).sendResetPasswordRequestToUser(
                eq(user.getEmail()),
                eq(user.getFirstName()),
                eq("http://localhost:5173/reset-password?token=jwt-token")
        );
    }

    @Test
    public void upDatePassword_ShouldCallUserServiceToUpdatePassword() {
        // given
        String token = "dummyJwtToken";
        String password = "newPassword";
        String passwordConfirm = "newPasswordConfirm";
        String email = "test@example.com";

        when(jwtService.extractUsername(token)).thenReturn(email);

        // when
        underTestAuthenticationService.upDatePassword(token, password, passwordConfirm);

        // then
        verify(userService).updatePassword(email, password, passwordConfirm);
    }

    @Test
    public void enableUser_ShouldCallUserServiceToEnableUser() {
        // given
        String token = "dummyJwtToken";
        String email = "test@example.com";

        when(jwtService.extractUsername(token)).thenReturn(email);

        // when
        underTestAuthenticationService.enableUser(token);

        // then
        verify(userService).enableUser(email);
    }

    @Test
    public void isPasswordAndPasswordConfirmMatches_ShouldReturnTrue_WhenPasswordsMatch() {
        // when
        boolean result = underTestAuthenticationService.isPasswordAndPasswordConfirmMatches(USER_REGISTER_REQUEST);

        // then
        assertTrue(result);
    }

    @Test
    public void isPasswordAndPasswordConfirmMatches_ShouldReturnFalse_WhenPasswordsDoNotMatch() {
        // given
        RegisterRequest registerRequest =
                new RegisterRequest(
                        "john",
                        "doe",
                        "john@example.com",
                        "password_11111111",
                        "password_22222222",
                        Role.ROLE_USER
                );


        // when
        boolean result = underTestAuthenticationService.isPasswordAndPasswordConfirmMatches(registerRequest);
        // then
        assertFalse(result);
    }

    @Test
    public void refreshToken_ShouldReturnNewAuthenticationResponse_WhenRefreshTokenIsValid() throws Exception {
        // given
        String refreshToken = "validRefreshToken";
        String accessToken = "newAccessToken";
        String email = "test@example.com";
        User user = USER_REGISTER_REQUEST.toUser();
        // create an instance of UserDetailsImpl based on the user in the PATIENT_REGISTER_REQUEST
        UserDetailsImpl userDetails = new UserDetailsImpl(user);

        when(request.getHeader("Authorization")).thenReturn("Bearer " + refreshToken);
        when(jwtService.extractUsername(refreshToken)).thenReturn(email);

        when(userService.loadUserByUsername(email)).thenReturn(userDetails);
        when(jwtService.isTokenValid(refreshToken, userDetails)).thenReturn(true);
        when(jwtService.generateAccessToken(user)).thenReturn(accessToken);

        // when
        AuthenticationResponse result = underTestAuthenticationService.refreshToken(request, response);

        // then
        assertNotNull(result);
        assertEquals(accessToken, result.accessToken());
        assertEquals(refreshToken, result.refreshToken());
        verify(tokenService).revokeAllUserTokens((userDetails).user());
        verify(tokenService).saveUserToken(user, accessToken);
        verify(response, never()).setStatus(anyInt());
        verify(printWriter, never()).write(anyString());
    }

    @Test
    public void refreshToken_ShouldReturnNull_WhenAuthorizationHeaderIsMissing() throws Exception {
        // given
        when(request.getHeader("Authorization")).thenReturn(null);
        when(response.getWriter()).thenReturn(printWriter); // Mock the getWriter() method to return a non-null PrintWriter


        // when
        AuthenticationResponse result = underTestAuthenticationService.refreshToken(request, response);

        // then
        assertNull(result);
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(printWriter).write("Missing or invalid Authorization header."); // Verify that the write() method is invoked on the PrintWriter
        verify(response, never()).sendError(anyInt(), anyString());
    }

    @Test
    public void refreshToken_ShouldReturnNull_WhenAuthorizationHeaderIsInvalid() throws Exception {
        // given
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        String invalidHeader = "InvalidHeader";

        when(request.getHeader("Authorization")).thenReturn(invalidHeader);
        when(response.getWriter()).thenReturn(printWriter); // Mock the getWriter() method to return a non-null PrintWriter


        // when
        AuthenticationResponse result = underTestAuthenticationService.refreshToken(request, response);

        // then
        assertNull(result);
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(printWriter).write("Missing or invalid Authorization header.");
        verify(response, never()).sendError(anyInt(), anyString());
    }

    @Test
    public void refreshToken_ShouldReturnNull_WhenRefreshTokenIsExpired() throws Exception {
        // given
        String refreshToken = "expiredRefreshToken";

        when(request.getHeader("Authorization")).thenReturn("Bearer " + refreshToken);
        when(jwtService.extractUsername(refreshToken)).thenThrow(ExpiredJwtException.class);

        // when
        AuthenticationResponse result = underTestAuthenticationService.refreshToken(request, response);

        // then
        assertNull(result);
        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED, "refresh token expired");
        verify(response, never()).setStatus(anyInt());
        verify(printWriter, never()).write(anyString());
    }

    @Test
    public void refreshToken_ShouldReturnNull_WhenRefreshTokenIsInvalid() throws Exception {
        // given
        String refreshToken = "invalidRefreshToken";

        when(request.getHeader("Authorization")).thenReturn("Bearer " + refreshToken);
        when(jwtService.extractUsername(refreshToken)).thenThrow(MalformedJwtException.class);


        // when
        AuthenticationResponse result = underTestAuthenticationService.refreshToken(request, response);

        // then
        assertNull(result);
        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED, "invalid refresh token.");
        verify(response, never()).setStatus(anyInt());
        verify(printWriter, never()).write(anyString());
    }

}
