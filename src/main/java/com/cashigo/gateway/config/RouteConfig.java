package com.cashigo.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteConfig {

    @Value("${expensio.base.uri}")
    private String expensioBaseUri;

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
                                                .tokenRelay()
                                )
                                .uri("http://localhost:8081")
                )
                .route("Expensio",
                        path -> path
                                .path("/expensio/**")
                                .filters(
                                        filter -> filter
                                                .rewritePath("/expensio/?(?<segment>.*)", "/${segment}")
                                                .tokenRelay()
                                )
                                .uri(expensioBaseUri)
                )
                .build();
    }

}
