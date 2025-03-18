package br.com.microservice.stateful_any_api.core.client;

import br.com.microservice.stateful_any_api.core.dto.AuthUserResponse;
import br.com.microservice.stateful_any_api.core.dto.TokenDTO;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;

@HttpExchange("/pi/auth")//sempre chama o localhost:8082
public interface TokenClient {

    @PostExchange("/token/validate")
    TokenDTO validateToken(@RequestHeader String accessToken);

    @GetExchange("/user")
    AuthUserResponse getAuthenticateUser(@RequestHeader String accessToken);

}
