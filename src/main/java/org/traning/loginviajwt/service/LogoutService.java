package org.traning.loginviajwt.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;
import org.traning.loginviajwt.config.JwtAuthenticationFilter;
import org.traning.loginviajwt.model.Token;
import org.traning.loginviajwt.repository.TokenRepository;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final TokenRepository tokenRepository;
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        logger.debug("Processing request to: {}", request.getRequestURI());

        // Retrieve the Authorization header from the request
        final String authorizationHeader = request.getHeader("Authorization");

        logger.debug("Authorization header: {}", authorizationHeader != null ? "present" : "missing");

        // If the Authorization header is missing or does not start with "Bearer ", continue the filter chain
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            logger.debug("No Bearer token found, continuing filter chain");
            return;
        }


            // Extract the JWT token from the Authorization header
            final String token = authorizationHeader.substring(7);

        Token token1 = tokenRepository.findByToken(token).orElse(null);

        if (token1 != null) {
            token1.setExpired(true);
            token1.setRevoked(true);
            tokenRepository.save(token1);
        }


    }
}
