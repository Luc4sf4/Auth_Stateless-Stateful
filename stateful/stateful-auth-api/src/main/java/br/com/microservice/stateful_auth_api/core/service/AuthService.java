package br.com.microservice.stateful_auth_api.core.service;

import br.com.microservice.stateful_auth_api.core.dto.AuthRequest;
import br.com.microservice.stateful_auth_api.core.dto.AuthUserResponse;
import br.com.microservice.stateful_auth_api.core.dto.TokenDTO;
import br.com.microservice.stateful_auth_api.core.dto.TokenData;
import br.com.microservice.stateful_auth_api.core.model.User;
import br.com.microservice.stateful_auth_api.core.repository.UserRepository;
import br.com.microservice.stateful_auth_api.infra.exception.AuthenticationException;
import br.com.microservice.stateful_auth_api.infra.exception.ValidationException;
import lombok.AllArgsConstructor;
import org.antlr.v4.runtime.Token;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static org.springframework.util.ObjectUtils.isEmpty;

@Service
@AllArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private final TokenService tokenService;


    public TokenDTO login(AuthRequest request) {

        var user = findByUsername(request.username());
        var accessToken = tokenService.createToken(user.getUsername());
        validatePassword(request.password(), user.getPassword());
        return new TokenDTO(accessToken);
    }

    public AuthUserResponse getAuthenticatedUser(String accessToken) {
        var tokenData = tokenService.getTokenData(accessToken);
        var user = findByUsername(tokenData.username());
        return new AuthUserResponse(user.getId(), user.getUsername());
    }

    public void logout(String accessToken){
        tokenService.deleteRedisToken(accessToken);
    }


    private User findByUsername(String username) {
        return userRepository
                .findByUsername(username)
                .orElseThrow(() -> new ValidationException("User not found"));
    }

    private void validatePassword(String rawPassword, String encodedPassword) {
        if (isEmpty(rawPassword)) {
            throw new ValidationException("The password must be informed!");
        }
        if (!passwordEncoder.matches(rawPassword, encodedPassword)) {
            throw new ValidationException("The password is not correct");
        }
    }

    public TokenDTO validateToken(String accesstoken) {
        validateExistingToken(accesstoken);
        var valid = tokenService.validateAccessToken(accesstoken);
        if (valid) {
            return new TokenDTO(accesstoken);
        } else {
            throw new AuthenticationException("Invalid token!");
        }
    }


    private void validateExistingToken(String accessToken) {
        if (isEmpty(accessToken)) {
            throw new ValidationException("The access token must be informed");
        }
    }

}
