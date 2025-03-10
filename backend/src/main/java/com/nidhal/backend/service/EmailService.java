package com.nidhal.backend.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.util.Calendar;

/**
 * Service class for sending emails to users. Uses JavaMailSender to send emails using SMTP.
 */
@Slf4j
@Service
public class EmailService {

    private final JavaMailSender javaMailSender;
    private final String senderEmail;

    public EmailService(JavaMailSender javaMailSender, @Value("${spring.mail.username}") String senderEmail) {
        this.javaMailSender = javaMailSender;
        this.senderEmail = senderEmail;
    }

    @Value("${verification-code.expiration.account-activation}")
    private int activationCodeExpirationTimeInMinutes;

    @Value("${verification-code.expiration.reset-password}")
    private int resetPasswordCodeExpirationTimeInMinutes;


    /**
     * Sends an activation code email to the specified user
     *
     * @param email     the email address of the user
     * @param firstName the first name of the user
     * @param code      the verification code
     */
    public void sendActivationCode(String email, String firstName, String code) {
        String ACTIVATION_EMAIL_TEMPLATE = "templates/activate-account-code.html";
        String subject = "Verify Your Account";

        sendEmailWithVerificationCode(email, firstName, subject, code, ACTIVATION_EMAIL_TEMPLATE, activationCodeExpirationTimeInMinutes);
    }

    /**
     * Sends a password reset code email to the specified user
     *
     * @param email     the email address of the user
     * @param firstName the first name of the user
     * @param code      the verification code
     */
    public void sendResetPasswordCode(String email, String firstName, String code) {
        String RESET_PASSWORD_EMAIL_TEMPLATE = "templates/reset-password-code.html";
        String subject = "Reset Your Password";

        sendEmailWithVerificationCode(email, firstName, subject, code, RESET_PASSWORD_EMAIL_TEMPLATE, resetPasswordCodeExpirationTimeInMinutes);
    }

    /**
     * Sends an email with a verification code using the specified template
     */
    private void sendEmailWithVerificationCode(
        String email, String firstName, String subject,
        String code, String template, int expirationMinutes) {

        String senderName = "Spring Boot 3 Team";
        String currentYear = String.valueOf(Calendar.getInstance().get(Calendar.YEAR));

        try {
            MimeMessage message = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(senderEmail, senderName);
            helper.setTo(email);
            helper.setSubject(subject);

            // Load email template from file
            ClassPathResource resource = new ClassPathResource(template);
            String content = new String(Files.readAllBytes(resource.getFile().toPath()));

            // Replace placeholders in email template with dynamic content
            content = content.replace("{{firstName}}", firstName);
            content = content.replace("{{verificationCode}}", code);
            content = content.replace("{{currentYear}}", currentYear);
            content = content.replace("{{expirationTimeInMinutes}}", String.valueOf(expirationMinutes));

            helper.setText(content, true);

            javaMailSender.send(message);
            log.info("Verification code email sent to {}", email);

        } catch (MessagingException | IOException exception) {
            log.error("Failed to send email to {}", email, exception);
        }
    }

    @Value("${jwt.expiration.enable-account}")
    long enableAccountExpirationTimeInMs;

    @Value("${jwt.expiration.reset-password}")
    private long resetPasswordExpirationTimeInMs;


    /**
     * Sends an activation link email to the specified user email address, using the provided activation link URL and
     * <p>
     * first name of the user.
     *
     * @param email          the email address of the user
     * @param firstName      the first name of the user
     * @param activationLink the activation link URL
     */
    public void sendActivationLink(String email, String firstName, String activationLink) {
        String ACTIVATION_EMAIL_TEMPLATE = "templates/activate-account.html";
        String subject = "Activate Your Account";

        sentEmailWithTemplate(email, firstName, subject, activationLink, ACTIVATION_EMAIL_TEMPLATE, enableAccountExpirationTimeInMs);
    }

    /**
     * Sends a password reset request email to the specified user email address, using the provided reset password link
     * <p>
     * URL and first name of the user.
     *
     * @param email             the email address of the user
     * @param firstName         the first name of the user
     * @param resetPasswordLink the reset password link URL
     */
    public void sendResetPasswordRequestToUser(String email, String firstName, String resetPasswordLink) {
        String RESET_PASSWORD_EMAIL_TEMPLATE = "templates/reset-password.html";
        String subject = "Reset Your Password";

        sentEmailWithTemplate(email, firstName, subject, resetPasswordLink, RESET_PASSWORD_EMAIL_TEMPLATE, resetPasswordExpirationTimeInMs);
    }


    /**
     * Sends an email with a specified HTML template to the specified user email address, using the provided email subject,
     * <p>
     * URL and template.
     *
     * @param email     the email address of the user
     * @param firstName the first name of the user
     * @param subject   the email subject
     * @param url       the URL used in the email template
     * @param template  the email HTML template
     */
    public void sentEmailWithTemplate(String email, String firstName, String subject, String url, String template, long expirationTimeInMs) {

        String senderName = "Spring Boot 3 Team";
        String currentYear = String.valueOf(Calendar.getInstance().get(Calendar.YEAR));
        int expirationTimeInMinutes = (int) (expirationTimeInMs / 60000);

        try {
            MimeMessage message = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(senderEmail, senderName);
            helper.setTo(email);
            helper.setSubject(subject);

            // Load email template from file
            ClassPathResource resource = new ClassPathResource(template);
            String content = new String(Files.readAllBytes(resource.getFile().toPath()));

            // Replace placeholders in email template with dynamic content
            content = content.replace("{{firstName}}", firstName);
            content = content.replace("{{activationLink}}", url);
            content = content.replace("{{currentYear}}", currentYear);
            content = content.replace("{{expirationTimeInMinutes}}", String.valueOf(expirationTimeInMinutes));

            helper.setText(content, true);

            javaMailSender.send(message);

        } catch (MessagingException | IOException exception) {
            log.error("Failed to send email to {}", email, exception);
        }
    }

}