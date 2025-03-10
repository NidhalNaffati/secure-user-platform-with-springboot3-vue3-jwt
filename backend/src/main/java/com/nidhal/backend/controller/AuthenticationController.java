package com.nidhal.backend.controller;


import com.nidhal.backend.requests.*;
import com.nidhal.backend.service.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody RegisterRequest request) {
        authenticationService.registerUser(request);
        return ResponseEntity.ok("Registration successful. Check your email for verification code.");
    }

    @PostMapping("/verify-user")
    public ResponseEntity<String> verifyAccount(@RequestBody VerifyAccountRequest request) {
        authenticationService.verifyUserAccount(request.getEmail(), request.getCode());
        return ResponseEntity.ok("Account verified successfully");
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        authenticationService.sendResetPasswordCodeToUser(request.getEmail());
        return ResponseEntity.ok("Password reset code sent to your email");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody ResetPasswordRequest request) {
        authenticationService.resetPassword(
            request.getEmail(),
            request.getCode(),
            request.getNewPassword(),
            request.getConfirmPassword()
        );
        return ResponseEntity.ok("Password reset successful");
    }

}
