package com.example.gateway;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class RouteLocatorGatewayConfig {

    @Bean
    public RouteLocator gatewayRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()

            .route("75b3f45e-bc35-34f2-a113-3e8a85bb2ccf", route -> route
                .path("/**")
                .uri("http://resourceserver:80"))

            .build();
    }
}
