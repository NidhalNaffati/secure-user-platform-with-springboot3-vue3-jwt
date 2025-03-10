package com.nidhal.backend.repository;

import com.nidhal.backend.entity.VerificationCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface VerificationCodeRepository extends JpaRepository<VerificationCode, Long> {

    Optional<VerificationCode> findByEmailAndCodeAndTypeAndUsedFalse(String email, String code, VerificationCode.CodeType type);

    List<VerificationCode> findAllByEmailAndTypeAndUsedFalse(String email, VerificationCode.CodeType type);
}