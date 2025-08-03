package org.traning.loginviajwt.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.traning.loginviajwt.dto.LoginUserDto;
import org.traning.loginviajwt.dto.RegisterUserDto;
import org.traning.loginviajwt.dto.VerifyUserDto;
import org.traning.loginviajwt.model.User;
import org.traning.loginviajwt.repository.UserRepository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;

@Service
public class AuthenticationService {


    private final UserRepository userRepository;

    private final EmailService emailService;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    public AuthenticationService(UserRepository userRepository,
            EmailService emailService,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.emailService = emailService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }


    public User registerUser(RegisterUserDto registerUserDto) {
        User user = new User();
        user.setEmail(registerUserDto.getEmail());
        user.setUsername(registerUserDto.getUsername());
        user.setPassword(passwordEncoder.encode(registerUserDto.getPassword()));
        user.setVerificationCode(generateVerificationCode());
        user.setVerificationStatus(LocalDateTime.now().plusMinutes(15));
        user.setEnabled(false);
        sendVerificationEmail(user);
        return userRepository.save(user);
    }

    private void sendVerificationEmail(User user) {
        String subject = "Please verify your email";
        String text = "To verify your email, please click the link below\n"
                + "http://localhost:8080/api/v1/auth/verify?code=" + user.getVerificationCode();
        try {
            emailService.sendEmail(user.getEmail(), subject, text);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String generateVerificationCode() {
        return String.valueOf(new Random().nextInt(100000, 999999));
    }

    public User authenticate(LoginUserDto input) {
        User user = userRepository.findByEmail(input.getEmail()).orElseThrow(
                () -> new RuntimeException("User not found"));
        if (!user.isEnabled()) {
            throw new RuntimeException("Account is not Verified");
        }
        if (LocalDateTime.now().isAfter(user.getVerificationStatus())) {
            throw new RuntimeException("Verification code expired");
        }
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(input.getEmail(), input.getPassword()));
        return user;

    }

    public void verifyUser(VerifyUserDto input) {
        Optional<User> user = userRepository.findByEmail(input.getEmail());
        if (user.isPresent()) {
            if (user.get().getVerificationStatus().isAfter(LocalDateTime.now())) {

                throw new RuntimeException("verification code expired");
            } else {
                if (user.get().getVerificationCode().equals(input.getVerificationCode())) {
                    user.get().setEnabled(true);
                    user.get().setVerificationStatus(null);
                    user.get().setVerificationCode(null);
                    userRepository.save(user.get());
                } else {
                    throw new RuntimeException("Invalid verification code");
                }
            }
        } else {
            throw new RuntimeException("User not found");
        }
    }

    public void resendVerificationCode(String email) {
        Optional<User> user = userRepository.findByEmail(email);
        if (user.isPresent()) {

            User user1 = user.get();
            if (user1.isEnabled()) {
                throw new RuntimeException("Account is already verified");
            }

            user.get().setVerificationCode(generateVerificationCode());
            user.get().setVerificationStatus(LocalDateTime.now().plusMinutes(15));
            sendVerificationEmail(user.get());
            userRepository.save(user.get());
        } else {
            throw new RuntimeException("User not found");
        }
    }


}
