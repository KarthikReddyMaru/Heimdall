package com.cashigo.gateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteConfig {

    @Bean
    RouteLocator routeLocator(RouteLocatorBuilder builder) {
        return builder
                .routes()
                .route("user",
                        path -> path
                                .path("/user/**")
                                .filters(
                                        filter -> filter
                                                .rewritePath("/user/?(?<segment>.*)", "/${segment}")
                                )
                                .uri("http://localhost:8081")
                )
                .build();
    }

}
