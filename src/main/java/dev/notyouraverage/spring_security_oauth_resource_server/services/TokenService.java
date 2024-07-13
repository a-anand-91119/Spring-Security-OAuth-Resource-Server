package dev.notyouraverage.spring_security_oauth_resource_server.services;

import org.springframework.security.core.Authentication;

public interface TokenService {
    String generateToken(Authentication authentication);
}
