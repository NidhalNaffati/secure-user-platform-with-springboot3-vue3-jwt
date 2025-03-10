package com.nidhal.backend.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Date;

import static jakarta.persistence.GenerationType.IDENTITY;

@Getter
@Setter
@Builder
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "verification_codes")
public class VerificationCode {
    @Id
    @GeneratedValue(strategy = IDENTITY)
    private Long id;

    @Column(length = 6)
    private String code;

    @Column(length = 100)
    private String email;

    @Enumerated(EnumType.STRING)
    private CodeType type;

    private Date expiryDate;

    private boolean used = false;

    public enum CodeType {
        ACCOUNT_ACTIVATION,
        PASSWORD_RESET
    }

    public boolean isExpired() {
        return new Date().after(this.expiryDate);
    }
}