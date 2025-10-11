package com.cashigo.gateway.config;

import com.cashigo.gateway.consts.ClientConstants;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.server.WebFilter;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;

@EnableWebFluxSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    @Value("${default.redirect.uri}")
    private String redirectUri;

    private final ClientConstants clientConstants;

    @Bean
    SecurityWebFilterChain webFilterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(
                        exchange -> exchange
                                .pathMatchers("/oauth2/authorization/**").permitAll()
                                .anyExchange().authenticated()
                )
                .cors(corsSpec -> corsSpec.configurationSource(
                        exchange -> {
                            CorsConfiguration corsConfiguration = new CorsConfiguration();
                            corsConfiguration.addAllowedMethod("*");
                            corsConfiguration.setAllowedHeaders(List.of("X-XSRF-TOKEN", "Content-Type", "Accept"));                            corsConfiguration.addAllowedOriginPattern("http://localhost:3000");
                            corsConfiguration.setAllowCredentials(true);
                            return corsConfiguration;
                        }
                ))
                .csrf(csrfSpec -> {
                    csrfSpec.csrfTokenRepository(cookieServerCsrfTokenRepository());
                    csrfSpec.csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler());
                })
                .oauth2Login(
                        oauth -> oauth
                                .authenticationSuccessHandler(successHandler())
                )
                .oauth2ResourceServer(
                        oAuth2ResourceServerSpec -> oAuth2ResourceServerSpec
                                .jwt(jwtSpec -> jwtSpec
                                        .jwkSetUri(clientConstants.getJwkSetUri())
                                        .jwtAuthenticationConverter(new ReactiveJwtAuthenticationConverter())
                                )
                )
                .logout(Customizer.withDefaults())
                .build();
    }

    @Bean
    RedirectServerAuthenticationSuccessHandler successHandler() {
        RedirectServerAuthenticationSuccessHandler handler = new RedirectServerAuthenticationSuccessHandler();
        handler.setLocation(
                UriComponentsBuilder
                        .fromUriString(redirectUri)
                        .build()
                        .toUri()
        );
        handler.setRequestCache(NoOpServerRequestCache.getInstance());
        return handler;
    }

    @Bean
    CookieServerCsrfTokenRepository cookieServerCsrfTokenRepository() {
        CookieServerCsrfTokenRepository tokenRepository = new CookieServerCsrfTokenRepository();
        tokenRepository.setCookieCustomizer(cookieCustomizer -> {
            cookieCustomizer.httpOnly(false);
            cookieCustomizer.secure(false);
            cookieCustomizer.sameSite("Lax");
        });
        return tokenRepository;
    }

    @Bean
    public WebFilter csrfCookieGeneratingFilter(CookieServerCsrfTokenRepository csrfTokenRepository) {
        return (exchange, chain) -> csrfTokenRepository.loadToken(exchange)
                .switchIfEmpty(csrfTokenRepository.generateToken(exchange)
                        .flatMap(token -> csrfTokenRepository.saveToken(exchange, token).thenReturn(token)))
                .then(chain.filter(exchange));
    }
}
