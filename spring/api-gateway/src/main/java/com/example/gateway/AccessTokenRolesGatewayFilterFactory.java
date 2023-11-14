package com.example.gateway;

import com.jayway.jsonpath.PathNotFoundException;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.json.JSONObject;
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

import static com.jayway.jsonpath.JsonPath.parse;
import static java.lang.String.format;
import static org.apache.commons.collections4.CollectionUtils.containsAll;
import static org.apache.commons.collections4.CollectionUtils.intersection;
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
    public GatewayFilter apply(Config config) {

        return new GatewayFilter() {

            @Override
            public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
                return exchange.getPrincipal()
                    .cast(JwtAuthenticationToken.class)
                    .map(token -> {
                        log.debug("<access-token attributes> {}", token.getTokenAttributes());

                        val attributes = token.getTokenAttributes();
                        val client = (String) attributes.get("azp");

                        val json = new JSONObject(attributes);
                        val context = parse(json.toString());

                        try {
                            List<String> roles = context.read(format("$['resource_access']['%s']['roles'][*]", client));
                            if (roles == null) throw new AccessDeniedException("Нет ролей токена");

                            val line = config.getName();
                            val strategy = config.getStrategy();
                            if (line == null || strategy == null) throw new AccessDeniedException("Нет ролей фильтра");

                            val names = List.of(line.split(" "));
                            switch (strategy) {
                                case ANY:
                                    if (intersection(roles, names).isEmpty()) {
                                        log.debug("Не пересекаются роли");
                                        throw new AccessDeniedException("Не пересекаются роли");
                                    }
                                    break;
                                case ALL:
                                    if (containsAll(names, roles)) {
                                        log.debug("Не представлены все роли");
                                        throw new AccessDeniedException("Не представлены все роли");
                                    }
                                    break;
                            }
                        } catch (PathNotFoundException e) {
                            throw new AccessDeniedException("Нет ролей токена", e);
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

    public enum Strategy {
        ANY, ALL
    }

    @Getter
    public static class Config extends NameConfig {

        private Strategy strategy = Strategy.ANY;

        public Config setStrategy(Strategy strategy) {
            this.strategy = strategy;
            return this;
        }
    }
}
