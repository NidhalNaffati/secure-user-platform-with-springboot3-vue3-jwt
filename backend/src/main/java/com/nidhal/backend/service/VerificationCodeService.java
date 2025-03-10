package com.nidhal.backend.service;

import com.nidhal.backend.entity.VerificationCode;
import com.nidhal.backend.exception.InvalidVerificationCodeException;
import com.nidhal.backend.repository.VerificationCodeRepository;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class VerificationCodeService {

    private final VerificationCodeRepository verificationCodeRepository;

    @Value("${verification-code.expiration.account-activation}")
    private int activationCodeExpirationInMinutes;

    @Value("${verification-code.expiration.reset-password}")
    private int resetPasswordCodeExpirationInMinutes;

    // Generate a random 6-digit code
    public String generateVerificationCode() {
        Random random = new Random();
        int code = 100000 + random.nextInt(900000); // Generates 6-digit number
        return String.valueOf(code);
    }

    // Save a new verification code for a user
    public VerificationCode createVerificationCode(String email, VerificationCode.CodeType type) {
        // Determine expiration time based on code type
        int expirationMinutes = type == VerificationCode.CodeType.ACCOUNT_ACTIVATION
            ? activationCodeExpirationInMinutes
            : resetPasswordCodeExpirationInMinutes;

        // Generate expiration date
        Date expiryDate = new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(expirationMinutes));
        log.info("Expiry date: {}", expiryDate);

        // Create new verification code
        VerificationCode verificationCode = VerificationCode.builder()
            .code(generateVerificationCode())
            .email(email)
            .type(type)
            .expiryDate(expiryDate)
            .used(false)
            .build();

        // Save to repository
        return verificationCodeRepository.save(verificationCode);
    }

    // Verify a code for a specific email and type
    public void verifyCode(String email, String code, VerificationCode.CodeType type) {
        VerificationCode verificationCode = verificationCodeRepository
            .findByEmailAndCodeAndTypeAndUsedFalse(email, code, type)
            .orElseThrow(() -> new InvalidVerificationCodeException("Invalid verification code"));

        if (verificationCode.isExpired()) {
            throw new InvalidVerificationCodeException("Verification code has expired");
        }

        // Mark code as used
        verificationCode.setUsed(true);
        verificationCodeRepository.save(verificationCode);
    }

    // Invalidate all codes for an email and type
    public void invalidateAllCodes(String email, VerificationCode.CodeType type) {
        verificationCodeRepository.findAllByEmailAndTypeAndUsedFalse(email, type)
            .forEach(code -> {
                code.setUsed(true);
                verificationCodeRepository.save(code);
            });
    }
}