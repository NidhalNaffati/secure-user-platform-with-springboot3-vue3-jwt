package com.nidhal.backend.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;

import java.util.Date;
import java.util.List;

import static jakarta.persistence.GenerationType.IDENTITY;

@Getter
@Setter
@Builder
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Table(
    name = "user_app",
    uniqueConstraints = {
        @UniqueConstraint(columnNames = "email")
    })
public class User {
    @Id
    @GeneratedValue(strategy = IDENTITY)
    private Long id;

    @Column(length = 30)
    private String firstName;

    @Column(length = 30)
    private String lastName;

    @Column(length = 100)
    private String email;

    @JsonIgnore // to prevent the password from being returned in the response body.
    private String password;

    @JsonIgnore
    @Transient
    private String confirmPassword;

    @Enumerated(EnumType.STRING)
    private Role role;

    /**
     * the user by default is not enable, until he activates his account.
     */
    @Column(name = "enabled")
    private boolean enabled = false; // by default is false, until the user activates his account via email verification.

    private boolean accountNonLocked = true; // by default is true, until the user is blocked by the admin.

    private int failedAttempts = 0;

    private Date createdAt;

    private Date updatedAt;


    @PrePersist
    protected void onCreate() {
        createdAt = new Date();
        updatedAt = new Date();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = new Date();
    }

    @JsonIgnore
    @OneToMany(mappedBy = "user")
    private List<Token> tokens;

}
