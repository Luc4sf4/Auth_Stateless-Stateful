package br.com.microservice.stateless_auth_api.core.service;

import br.com.microservice.stateless_auth_api.core.dto.AuthRequest;
import br.com.microservice.stateless_auth_api.core.dto.TokenDTO;
import br.com.microservice.stateless_auth_api.core.repository.UserRepository;
import br.com.microservice.stateless_auth_api.infra.exception.ValidationException;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import static org.springframework.util.ObjectUtils.isEmpty;

@Service
@AllArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;  //permite trabalhar com BCrypt
    private final JWTservice jwTservice;

    public TokenDTO login(AuthRequest request) {
        var user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new ValidationException("User not found"));
        var accessToken = jwTservice.createToken(user);
        validatePassword(request.password(), user.getPassoword());
        return new TokenDTO(accessToken);
    }

    //senha que o usuario nos passa, senha que encriptada pelo Bcrypt
    private void validatePassword(String rawPassword, String encodedPassword) {

        //Se as senhas nao batem, lance uma exception
        //"!" representa negacao
        if (!passwordEncoder.matches(rawPassword, encodedPassword)) {
            throw new ValidationException("The password is not correct");
        }

    }

    public TokenDTO validateToken(String accessToken){
        validateExistingToken(accessToken);
        jwTservice.validateAccessToken(accessToken);
        return new TokenDTO(accessToken);
    }

    private void validateExistingToken(String accessToken){
        if(isEmpty(accessToken)){
            throw new ValidationException("The access token must be informed");
        }
    }

}
