package com.nidhal.backend.service;


import com.nidhal.backend.entity.User;
import com.nidhal.backend.exception.AccountLockedException;
import com.nidhal.backend.exception.EmailAlreadyExistsException;
import com.nidhal.backend.exception.PasswordDontMatchException;
import com.nidhal.backend.exception.UserNotFoundException;
import com.nidhal.backend.entity.UserDetailsImpl;
import com.nidhal.backend.repository.TokenRepository;
import com.nidhal.backend.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * The UserService class handles business logic related to user accounts, such as saving and retrieving users,
 * updating passwords, and validating user credentials.
 */
@Slf4j
@Service
@AllArgsConstructor
public class UserService implements UserDetailsService {

    public static final int MAX_FAILED_ATTEMPTS = 5;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenRepository tokenRepository;

    /**
     * Loads a user from the database by their email address.
     *
     * @param username the username identifying the user whose data is required.
     * @return a UserDetailsImpl object containing the user's data.
     * @throws UsernameNotFoundException if no user with the specified email address is found.
     */
    @Override
    public UserDetailsImpl loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("loading user by username: {}", username);
        User user = userRepository
            .findByEmail(username) // find the user by email
            .orElseThrow(() -> new UsernameNotFoundException("user not found")); // if the user is not found, throw an exception
        return new UserDetailsImpl(user);
    }

    /**
     * Determines whether a user account with the specified email address already exists.
     *
     * @param email the email address to check for
     * @return true if a user account with the specified email address exists, false otherwise
     */
    public boolean emailExists(String email) {
        return userRepository.existsByEmail(email);
    }


    /**
     * Finds a user account by the specified email address.
     *
     * @param email the email address to search for
     * @return the User object corresponding to the specified email address
     * @throws UserNotFoundException if no user account with the specified email address exists
     */
    public User findUserByEmail(String email) {
        return userRepository
            .findByEmail(email)
            .orElseThrow(() -> new UserNotFoundException("no user with email: " + email + " found"));
    }

    /**
     * Saves a new user account to the database, after checking that no other account with the same email address exists.
     *
     * @param user the User object to save
     * @throws EmailAlreadyExistsException if a user account with the same email address already exists
     */
    public User saveUser(User user) {
        String email = user.getEmail(); // get the email that the user have provided

        // check if the email already exists
        if (emailExists(email)) {
            // if the email already exists, throw an exception
            throw new EmailAlreadyExistsException();
        } else { // if the email doesn't exist, save the user

            String password = user.getPassword(); // get the password that the user have provided
            user.setPassword(passwordEncoder.encode(password)); // encode the password

           /* Set<Role> roles = user.getRoles(); // get the roles that the user have provided

            user.setRoles(roles); // set the roles*/

            userRepository.save(user); // save the user
        }
        return user;
    }

    /**
     * Updates the password for the user account with the specified email address, after validating that the new password and the
     * confirmation password match.
     *
     * @param email           the email address of the user account to update
     * @param password        the new password to set
     * @param confirmPassword the confirmation password to match against the new password
     * @throws UserNotFoundException      if no user account with the specified email address exists
     * @throws PasswordDontMatchException if the new password and the confirmation password do not match
     */
    public void updatePassword(String email, String password, String confirmPassword) {

        if (emailExists(email)) { // check if the email exists
            User user = findUserByEmail(email); // get the user

            if (password.equals(confirmPassword)) { // check if the password and the confirmPassword matches.
                user.setPassword(passwordEncoder.encode(confirmPassword)); // encode the new password
                userRepository.save(user); // save the user
            } else { // if the password doesn't match, throw an exception
                throw new PasswordDontMatchException();
            }
        } else { // if the email doesn't exist, throw an exception
            throw new UserNotFoundException("no user with email: " + email + " found");
        }
    }

    /**
     * Validates the specified email address and password, and returns the corresponding User object if the credentials are valid.
     *
     * @param email    the email address to validate
     * @param password the password to validate
     * @return the User object corresponding to the specified email address and password
     * @throws BadCredentialsException if the specified email address and password are invalid
     * @throws AccountLockedException  if the user account is locked due to multiple failed login attempts
     */
    public User validateCredentials(String email, String password) {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        if (!passwordEncoder.matches(password, user.getPassword())) { // If the password is incorrect
            // Increment failed attempts
            user.setFailedAttempts(user.getFailedAttempts() + 1);

            userRepository.save(user);

            if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) { // If the user has failed to log in 5 times
                // Lock the account
                log.info("Locking account for user: {}", email);
                user.setAccountNonLocked(false);
                userRepository.save(user);
                throw new AccountLockedException();
            }

            throw new BadCredentialsException("Invalid credentials");
        }

        // Reset failed attempts on successful login
        user.setFailedAttempts(0);
        userRepository.save(user);

        return user;
    }

    /**
     * Enables the user account with the specified email address.
     *
     * @param email the email address of the user account to enable
     * @throws UserNotFoundException if no user account with the specified email address exists
     */
    public void enableUser(String email) {
        // get the user by email
        User user = findUserByEmail(email);
        // enable the user
        user.setEnabled(true);
        // save the user
        userRepository.save(user);
    }

    public void lockUser(String email) {
        // get the user by email
        User user = findUserByEmail(email);
        // lock the user
        user.setAccountNonLocked(false);
        // save the user
        userRepository.save(user);
    }

    public void unlockUser(String email) {
        // get the user by email
        User user = findUserByEmail(email);
        // unlock the user
        user.setAccountNonLocked(true);
        user.setFailedAttempts(0);
        // save the user
        userRepository.save(user);
    }

    public List<User> getAllUsers() {
        return userRepository.findAllUsers();
    }

    public List<User> getLockedUsers() {
        return userRepository.findLockedUsers();
    }

    public List<User> getUnlockedUsers() {
        return userRepository.findUnlockedUsers();
    }

    @Transactional
    public void deleteUser(String email) {
        // get the user by email
        User user = findUserByEmail(email);
        long userId = user.getId();

        // First, delete the tokens associated with the user
        tokenRepository.deleteAllByUser(userId);

        // Then, delete the user
        userRepository.delete(user);
    }
}