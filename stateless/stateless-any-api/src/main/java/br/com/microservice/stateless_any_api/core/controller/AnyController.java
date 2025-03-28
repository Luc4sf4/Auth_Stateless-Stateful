package br.com.microservice.stateless_any_api.core.controller;

import br.com.microservice.stateless_any_api.core.dto.AnyResponse;
import br.com.microservice.stateless_any_api.core.service.AnyServices;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
@RequestMapping("api/resource")
public class AnyController {

    private final AnyServices anyServices;

    @GetMapping
    public AnyResponse getResource(@RequestHeader String accessToken) {
        return anyServices.getData(accessToken);
    }
}
