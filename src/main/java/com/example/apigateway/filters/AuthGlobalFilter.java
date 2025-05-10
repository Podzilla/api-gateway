package com.example.apigateway.filters;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@Slf4j
@RequiredArgsConstructor
public class AuthGlobalFilter implements GlobalFilter {

    private final WebClient authWebClient;

    private List<String> excludedPaths;

    @Value("${excluded.paths}")
    public void setExcludedPaths(List<String> excludedPaths) {
        this.excludedPaths = excludedPaths;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String token = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);
        String path = exchange.getRequest().getPath().value();
        boolean isExcluded = excludedPaths.stream().anyMatch(path::startsWith);
        if (isExcluded) {
            log.debug("Path {} is excluded from AuthGlobalFilter. Skipping token validation.", path);
            return chain.filter(exchange); // Pass through without authentication for excluded paths
        }
        if (token == null) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        return authWebClient
                .get()
                .uri("/api/auth/me")
                .header(HttpHeaders.AUTHORIZATION, token)
                .retrieve()
                .onStatus(status -> status != HttpStatus.OK,
                        resp -> Mono.error(new RuntimeException("Unauthorized")))
                .bodyToMono(Void.class)
                .then(chain.filter(exchange))
                .onErrorResume(err -> {
                    log.warn("Auth failed: {}", err.getMessage());
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                });
    }
}
