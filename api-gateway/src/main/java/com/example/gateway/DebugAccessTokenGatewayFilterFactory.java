package com.example.gateway;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;


@Slf4j
@Component
public class DebugAccessTokenGatewayFilterFactory extends AbstractGatewayFilterFactory<Object> {

    @Override
    public GatewayFilter apply(Object config) {

        return (exchange, chain) -> exchange.getPrincipal()
            .cast(JwtAuthenticationToken.class)
            .map(token -> {
                log.info("<TOKEN>: {}", token.getTokenAttributes());
                return exchange;
            })
            .flatMap(chain::filter);
    }
}
