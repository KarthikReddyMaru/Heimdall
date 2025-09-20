package com.cashigo.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.web.util.UriComponentsBuilder;

@EnableWebFluxSecurity
@Configuration
public class SecurityConfig {

    @Bean
    SecurityWebFilterChain webFilterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(
                        exchange -> exchange
                                .pathMatchers("/oauth2/authorization/**").permitAll()
                                .anyExchange().authenticated()
                )
                .oauth2Login(
                        oauth -> oauth
                                .authenticationSuccessHandler(successHandler())
                )
                .logout(Customizer.withDefaults())
                .build();
    }

    @Bean
    RedirectServerAuthenticationSuccessHandler successHandler() {
        RedirectServerAuthenticationSuccessHandler handler = new RedirectServerAuthenticationSuccessHandler();
        handler.setLocation(
                UriComponentsBuilder
                        .fromPath("/expensio/transaction")
                        .queryParam("pageNum", 0)
                        .build()
                        .toUri()
        );
        handler.setRequestCache(NoOpServerRequestCache.getInstance());
        return handler;
    }

}
