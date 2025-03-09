package com.nidhal.backend.service;


import com.nidhal.backend.entity.User;
import com.nidhal.backend.exception.AccountLockedException;
import com.nidhal.backend.exception.EmailAlreadyExistsException;
import com.nidhal.backend.exception.PasswordDontMatchException;
import com.nidhal.backend.exception.UserNotFoundException;
import com.nidhal.backend.entity.UserDetailsImpl;
import com.nidhal.backend.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static com.nidhal.backend.service.UserService.MAX_FAILED_ATTEMPTS;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserService underTestUserService;


    @Test
    void testLoadUserByUsername_ExistingUser() {
        // given
        String email = "test@example.com";
        User user = new User();
        user.setEmail(email);

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        // when
        UserDetailsImpl userDetails = underTestUserService.loadUserByUsername(email);

        // then
        assertNotNull(userDetails);
        assertEquals(email, userDetails.getUsername());
        verify(userRepository).findByEmail(email);
    }

    @Test
    void testLoadUserByUsername_NonExistingUser() {
        // given
        String email = "test@example.com";
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

        // when
        assertThrows(UsernameNotFoundException.class,
          () -> underTestUserService.loadUserByUsername(email)
        );

        // then
        verify(userRepository).findByEmail(email);
    }

    @Test
    void testEmailExists_ExistingEmail() {
        // given
        String email = "test@example.com";
        when(userRepository.existsByEmail(email)).thenReturn(true);

        // when
        assertTrue(underTestUserService.emailExists(email));

        // then
        verify(userRepository).existsByEmail(email);
    }

    @Test
    void testEmailExists_NonExistingEmail() {
        // given
        String email = "test@example.com";
        when(userRepository.existsByEmail(email)).thenReturn(false);

        // when
        assertFalse(underTestUserService.emailExists(email));

        // then
        verify(userRepository).existsByEmail(email);
    }

    @Test
    void testFindUserByEmail_ExistingUser() {
        // given
        String email = "test@example.com";
        User user = new User();
        user.setEmail(email);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        // when
        User foundUser = underTestUserService.findUserByEmail(email);

        // then
        assertNotNull(foundUser);
        assertEquals(email, foundUser.getEmail());
        verify(userRepository).findByEmail(email);
    }

    @Test
    void testFindUserByEmail_NonExistingUser() {
        // given
        String email = "test@example.com";
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

        // when
        assertThrows(UserNotFoundException.class, () -> underTestUserService.findUserByEmail(email));

        // then
        verify(userRepository).findByEmail(email);
    }

    @Test
    void testSaveUser_NewUser() {
        // given
        String password = "password";
        String email = "test@example.com";

        User user = new User();
        user.setEmail(email);
        user.setPassword(password);


        when(userRepository.existsByEmail(email)).thenReturn(false);
        when(passwordEncoder.encode(password)).thenReturn("encodedPassword");
        when(userRepository.save(user)).thenReturn(user);

        // when
        User savedUser = underTestUserService.saveUser(user);

        // then
        assertNotNull(savedUser);
        assertEquals(email, savedUser.getEmail());
        assertEquals("encodedPassword", savedUser.getPassword());
        verify(userRepository).existsByEmail(email);
        verify(passwordEncoder).encode(password);
        verify(userRepository).save(user);
    }

    @Test
    void testSaveUser_ExistingEmail() {
        // given
        String email = "test@example.com";
        User user = new User();
        user.setEmail(email);
        user.setPassword("password");

        when(userRepository.existsByEmail(email)).thenReturn(true);

        // when
        assertThrows(EmailAlreadyExistsException.class,
          () -> underTestUserService.saveUser(user)
        );

        // then
        verify(userRepository).existsByEmail(email);
        verify(userRepository, never()).save(user);
    }


    @Test
    void testSaveNewDoctor_ExistingEmail() {
        // given
        String email = "test@example.com";

        User user = new User();
        user.setEmail(email);

        when(userRepository.existsByEmail(email)).thenReturn(true);

        // when
        assertThrows(EmailAlreadyExistsException.class, () -> underTestUserService.saveUser(user));

        // then
        verify(userRepository).existsByEmail(email);
        verify(userRepository, never()).save(user);
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void testUpdatePassword_WithMatchingPasswords_ShouldUpdateUserPassword() {
        // given
        String email = "test@example.com";
        String password = "newPassword";
        String confirmPassword = "newPassword";

        User user = new User();
        user.setEmail(email);
        user.setPassword("oldPassword");

        when(userRepository.existsByEmail(email)).thenReturn(true);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.encode(confirmPassword)).thenReturn("encodedPassword");

        // when
        assertDoesNotThrow(() -> underTestUserService.updatePassword(email, password, confirmPassword));

        // then
        verify(userRepository, times(1)).existsByEmail(email);
        verify(userRepository, times(1)).findByEmail(email);
        verify(passwordEncoder, times(1)).encode(confirmPassword);
        verify(userRepository, times(1)).save(user);
        assertEquals("encodedPassword", user.getPassword());
    }

    @Test
    void testUpdatePassword_WithNonMatchingPasswords_ShouldThrowPasswordDontMatchException() {
        // given
        String email = "test@example.com";
        String password = "newPassword";
        String confirmPassword = "differentPassword";

        User user = new User();
        user.setEmail(email);
        user.setPassword("oldPassword");

        when(userRepository.existsByEmail(email)).thenReturn(true);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        // when
        assertThrows(PasswordDontMatchException.class,
          () -> underTestUserService.updatePassword(email, password, confirmPassword)
        );

        // then
        verify(userRepository, times(1)).existsByEmail(email);
        verify(userRepository, times(1)).findByEmail(email);
        verifyNoInteractions(passwordEncoder);
        verifyNoMoreInteractions(userRepository);
    }


    @Test
    void testUpdatePassword_WithNonExistingUser_ShouldThrowUserNotFoundException() {
        // given
        String email = "nonexisting@example.com";
        String password = "newPassword";
        String confirmPassword = "newPassword";

        when(userRepository.existsByEmail(email)).thenReturn(false);

        // when
        assertThrows(UserNotFoundException.class,
          () -> underTestUserService.updatePassword(email, password, confirmPassword)
        );

        // then
        verify(userRepository, times(1)).existsByEmail(email);
        verifyNoInteractions(passwordEncoder);
        verifyNoMoreInteractions(userRepository); // Use verifyNoMoreInteractions to ensure no additional interactions occur
    }


    @Test
    void testValidateCredentials_ValidCredentials() {
        // given
        String email = "test@example.com";
        String password = "password";

        User user = new User();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(password, user.getPassword())).thenReturn(true);

        // when
        User validatedUser = underTestUserService.validateCredentials(email, password);

        // then
        assertNotNull(validatedUser);
        assertEquals(email, validatedUser.getEmail());
        assertEquals(passwordEncoder.encode(password), validatedUser.getPassword());
        verify(userRepository).findByEmail(email);
        verify(passwordEncoder).matches(password, user.getPassword());
    }

    @Test
    void testValidateCredentials_InvalidCredentials() {
        // given
        String email = "test@example.com";
        String password = "password";
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

        // when
        assertThrows(BadCredentialsException.class,
          () -> underTestUserService.validateCredentials(email, password)
        );

        // then
        verify(userRepository).findByEmail(email);
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void testValidateCredentials_PasswordMismatch() {
        // given
        String email = "test@example.com";
        String password = "password";

        User user = new User();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode("differentPassword"));

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(password, user.getPassword())).thenReturn(false);

        // when
        assertThrows(BadCredentialsException.class, () -> underTestUserService.validateCredentials(email, password));

        // then
        verify(userRepository).findByEmail(email);
        verify(passwordEncoder).matches(password, user.getPassword());
    }

    @Test
    void testValidateCredentials_LockUserAfterFailedAttempts() {
        // given
        var email = "fakeemail@example.com";
        var password = "wrongPassword";

        User user = new User();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setFailedAttempts(MAX_FAILED_ATTEMPTS - 1);
        user.setAccountNonLocked(true);

        // when
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        // then
        User lockedUser = underTestUserService.findUserByEmail(email);

        assertThrows(AccountLockedException.class, () -> underTestUserService.validateCredentials(email, password));
        assertFalse(lockedUser.isAccountNonLocked()); // Ensure account is unlocked after successful login
        assertEquals(5, lockedUser.getFailedAttempts()); // Ensure failed attempts are reset
        verify(userRepository, times(2)).save(user);
    }


    @Test
    void testEnableUser() {
        // given
        String email = "test@example.com";
        User user = new User();
        user.setEmail(email);
        user.setEnabled(false);

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(userRepository.save(user)).thenReturn(user);

        // when
        assertDoesNotThrow(() -> underTestUserService.enableUser(email));

        // then
        assertTrue(user.isEnabled());
        verify(userRepository).findByEmail(email);
        verify(userRepository).save(user);
    }

    @Test
    void testEnableUser_UserNotFound() {
        // given
        String email = "test@example.com";
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

        // when
        assertThrows(UserNotFoundException.class,
          () -> underTestUserService.enableUser(email)
        );

        // then
        verify(userRepository).findByEmail(email);
        verify(userRepository, never()).save(any(User.class));
    }
}
