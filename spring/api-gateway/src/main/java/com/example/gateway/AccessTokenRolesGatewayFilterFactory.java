package com.example.gateway;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static com.example.gateway.AccessTokenRolesGatewayFilterFactory.Strategy.ANY;
import static org.apache.commons.collections4.CollectionUtils.containsAll;
import static org.apache.commons.collections4.CollectionUtils.containsAny;
import static org.springframework.cloud.gateway.support.GatewayToStringStyler.filterToStringCreator;


@Slf4j
@Component
public class AccessTokenRolesGatewayFilterFactory extends AbstractGatewayFilterFactory<AccessTokenRolesGatewayFilterFactory.Config> {

    private static final String STRATEGY_KEY = "strategy";

    public AccessTokenRolesGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList(NAME_KEY, STRATEGY_KEY);
    }

    @Override
    public GatewayFilter apply(AccessTokenRolesGatewayFilterFactory.Config config) {

        return new GatewayFilter() {

            @Override
            public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
                return exchange.getPrincipal()
                    .cast(JwtAuthenticationToken.class)
                    .map(token -> {
                        val tokenConfig = tokenConfig(token);
                        log.debug("<token-roles> {} {}", tokenConfig.userName(), tokenConfig.roles());

                        val filterConfig = filterConfig(config);
                        log.debug("<filter-roles> {} {}", filterConfig.strategy(), filterConfig.roles());

                        switch (filterConfig.strategy()) {
                            case ANY:
                                if (! containsAny(tokenConfig.roles(), filterConfig.roles())) {
                                    log.debug("Не пересекаются роли");
                                    throw new AccessDeniedException("Не пересекаются роли");
                                }
                                break;
                            case ALL:
                                if (! containsAll(tokenConfig.roles(), filterConfig.roles())) {
                                    log.debug("Не представлены все роли");
                                    throw new AccessDeniedException("Не представлены все роли");
                                }
                                break;
                        }

                        return exchange;
                    })
                    .flatMap(chain::filter);
            }

            @Override
            public String toString() {
                return filterToStringCreator(AccessTokenRolesGatewayFilterFactory.this)
                    .append(config.getName(), config.getStrategy()).toString();
            }
        };
    }

    @SuppressWarnings("unchecked")
    TokenConfig tokenConfig(JwtAuthenticationToken token) {
        try {
            val attributes = (Map<String, Object>) token.getTokenAttributes();

            val username = (String) attributes.get("preferred_username");
            val access = (Map<String, Object>) attributes.get("resource_access");
            val client = (Map<String, Object>) access.get((String) attributes.get("azp"));

            return new TokenConfig(username, (List<String>) client.get("roles"));
        } catch (RuntimeException e) {
            throw new AccessDeniedException("Нет ролей клиента", e);
        }
    }

    FilterConfig filterConfig(Config config) {
        val name = config.getName(); if (name == null)
            throw new AccessDeniedException("Нет ролей фильтра");

        val strategy = config.getStrategy(); if (strategy == null)
            throw new AccessDeniedException("Нет стратегии фильтра");

        val roles = Stream.of(name.split(" "))
            .map(String::trim)
            .toList();

        return new FilterConfig(config.getStrategy(), roles);
    }


    public enum Strategy {
        ANY, ALL
    }

    @Getter
    public static class Config extends NameConfig {

        private Strategy strategy = ANY;

        public Config setStrategy(Strategy strategy) {
            this.strategy = strategy;
            return this;
        }
    }

    private record TokenConfig(String userName, List<String> roles) { }

    private record FilterConfig(Strategy strategy, List<String> roles) { }
}
