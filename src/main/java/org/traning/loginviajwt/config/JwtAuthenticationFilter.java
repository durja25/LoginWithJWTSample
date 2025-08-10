package org.traning.loginviajwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.traning.loginviajwt.service.JwtService;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final HandlerExceptionResolver handlerExceptionResolver;

    private final JwtService jwtService;

    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(HandlerExceptionResolver handlerExceptionResolver,
            JwtService jwtService,
            UserDetailsService userDetailsService) {

        this.handlerExceptionResolver = handlerExceptionResolver;
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }


    /**
     * Filters incoming requests and applies JWT authentication.
     *
     * @param request     the HTTP request
     * @param response    the HTTP response
     * @param filterChain the filter chain
     * @throws ServletException if an error occurs during the filtering process
     * @throws IOException      if an I/O error occurs during the filtering process
     */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        
        logger.debug("Processing request to: {}", request.getRequestURI());
        
        // Retrieve the Authorization header from the request
        final String authorizationHeader = request.getHeader("Authorization");
        
        logger.debug("Authorization header: {}", authorizationHeader != null ? "present" : "missing");

        // If the Authorization header is missing or does not start with "Bearer ", continue the filter chain
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            logger.debug("No Bearer token found, continuing filter chain");
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // Extract the JWT token from the Authorization header
            final String token = authorizationHeader.substring(7);

            // Extract the username from the JWT token
            final String username = jwtService.extractUsername(token);

            // Get the current authentication from the SecurityContext
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            // If the username is not empty, load the user details
            if (!StringUtils.isEmpty(username)) {
                logger.debug("Loading user details for username: {}", username);
                try {
                    var userDetails = userDetailsService.loadUserByUsername(username);
                    logger.debug("User details loaded successfully: {}", userDetails.getUsername());

                    // If the token is valid, create an authentication token and set it in the SecurityContext
                    if (jwtService.validateToken(token, userDetails)) {
                        logger.debug("Token validated successfully for user: {}", userDetails.getUsername());
                        
                        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        
                        logger.debug("Created authentication token with authorities: {}", userDetails.getAuthorities());

                        usernamePasswordAuthenticationToken.setDetails(
                                new WebAuthenticationDetailsSource().buildDetails(request));
                        
                        SecurityContext context = SecurityContextHolder.createEmptyContext();
                        context.setAuthentication(usernamePasswordAuthenticationToken);
                        SecurityContextHolder.setContext(context);
                        
                        logger.debug("SecurityContext set with authentication: {}", 
                            SecurityContextHolder.getContext().getAuthentication() != null ? "SUCCESS" : "FAILED");
                    } else {
                        logger.warn("Token validation failed for user: {}", username);
                    }
                } catch (Exception e) {
                    logger.error("Error loading user details for user: {}", username, e);
                }
            } else {
                logger.warn("Username is empty or null");
            }

            // Continue the filter chain
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            // Resolve any exceptions that occur during the filtering process
            handlerExceptionResolver.resolveException(request, response, null, e);
        }
    }
}
