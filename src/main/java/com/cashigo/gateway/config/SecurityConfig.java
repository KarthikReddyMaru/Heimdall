package com.cashigo.gateway.config;

import org.springframework.cache.support.NoOpCache;
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
                                .pathMatchers("/oauth2/authorization/**","/login/oauth2/code/**").permitAll()
                                .anyExchange().authenticated()
                )
                .oauth2Login(
                        oauth -> oauth
                                .authenticationSuccessHandler(successHandler())
                )
                .build();
    }

    @Bean
    RedirectServerAuthenticationSuccessHandler successHandler() {
        RedirectServerAuthenticationSuccessHandler handler = new RedirectServerAuthenticationSuccessHandler();
        handler.setLocation(UriComponentsBuilder.fromPath("/user/myprofile").build().toUri());
        handler.setRequestCache(NoOpServerRequestCache.getInstance());
        return handler;
    }

}
