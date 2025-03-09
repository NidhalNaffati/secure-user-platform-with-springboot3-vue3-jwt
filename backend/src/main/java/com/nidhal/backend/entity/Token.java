package com.nidhal.backend.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import static jakarta.persistence.GenerationType.IDENTITY;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Token {
    @Id
    @GeneratedValue(strategy = IDENTITY)
    public Long id;

    @Column(unique = true)
    private String token;

    private boolean revoked;

    private boolean expired;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;
}
