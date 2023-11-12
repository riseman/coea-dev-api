package com.example.gateway;

import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@RequiredArgsConstructor
@Configuration
public class RouteLocatorGatewayConfig {

    private final DebugAccessTokenGatewayFilterFactory debugAccessTokenGatewayFilterFactory;


    @Bean
    public RouteLocator gatewayRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()

            .route("75b3f45e-bc35-34f2-a113-3e8a85bb2ccf", route -> route
                .path("/**")
                .filters(spec -> spec.filter(debugAccessTokenGatewayFilterFactory.apply(new Object())))
                .uri("http://resourceserver:80"))

            .build();
    }
}
