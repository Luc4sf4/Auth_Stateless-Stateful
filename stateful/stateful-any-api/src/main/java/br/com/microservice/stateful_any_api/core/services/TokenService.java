package br.com.microservice.stateful_any_api.core.services;

import br.com.microservice.stateful_any_api.core.client.TokenClient;
import br.com.microservice.stateful_any_api.core.dto.AuthUserResponse;
import br.com.microservice.stateful_any_api.infra.exception.AuthenticationException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@AllArgsConstructor
public class TokenService {

    private final TokenClient tokenClient;

    public void validateToken(String token) {
        try {
            log.info("Sending request for token validation {}", token);
            var response = tokenClient.validateToken(token);
            log.info("Token is valid {}", response.accessToken());
        } catch (Exception e) {
            throw new AuthenticationException("Auth error: " + e.getMessage());
        }
    }


    public AuthUserResponse getAuthenticatedUser(String token) {
        try {

            log.info("Sending request for Auth user: {}", token);
            var response = tokenClient.getAuthenticateUser(token);
            log.info("Auth user found: {} and Token {}", response.toString(), token);

            return response;
        } catch (Exception e) {
            throw new AuthenticationException("Error to get authenticated user: " + e.getMessage());
        }
    }

}
