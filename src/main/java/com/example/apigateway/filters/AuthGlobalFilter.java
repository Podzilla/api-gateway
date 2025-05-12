package com.example.apigateway.filters;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
public class AuthGlobalFilter implements GlobalFilter {

    private final WebClient authWebClient;

    private final List<String> excludedPaths = List.of("/api/auth");

    public AuthGlobalFilter(WebClient authWebClient) {
        this.authWebClient = authWebClient;
    }

    @Override
   public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        boolean isExcluded = excludedPaths.stream().anyMatch(path::startsWith);
        if (isExcluded) {
            return chain.filter(exchange);
        }

        HttpHeaders incoming = exchange.getRequest().getHeaders();

        return authWebClient
                .get()
                .uri("/api/auth/me")
                .headers(headers -> headers.addAll(incoming))
                .retrieve()
                .onStatus(status -> status != HttpStatus.OK,
                        resp -> Mono.error(new RuntimeException("Unauthorized")))
                .bodyToMono(Void.class)
                .then(chain.filter(exchange))
                .onErrorResume(err -> {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                });
    }

}
