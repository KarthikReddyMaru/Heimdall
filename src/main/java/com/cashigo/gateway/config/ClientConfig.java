package com.cashigo.gateway.config;

import com.cashigo.gateway.consts.ClientConstants;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class ClientConfig {

    private final ClientConstants clientConstants;

    @Bean
    ClientRegistration keyCloakClientRegistration() {
        return ClientRegistration
                .withRegistrationId("keycloak")
                .clientId(clientConstants.getClientId())
                .clientSecret(clientConstants.getClientSecret())
                .authorizationUri(clientConstants.getAuthorizationUri())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(clientConstants.getRedirectUri())
                .tokenUri(clientConstants.getTokenUri())
                .jwkSetUri(clientConstants.getJwkSetUri())
                .userInfoUri(clientConstants.getUserInfoUri())
                .scope(List.of("offline_access", "openid"))
                .userNameAttributeName(clientConstants.getUserNameAttributeName())
                .issuerUri(clientConstants.getIssuerUri())
                .build();
    }

    @Bean
    ReactiveClientRegistrationRepository clientRegistrationRepository(ClientRegistration keyCloakClientRegistration) {
        return new InMemoryReactiveClientRegistrationRepository(keyCloakClientRegistration);
    }

    @Bean
    ReactiveOAuth2AuthorizedClientService authorizedClientService(ReactiveClientRegistrationRepository clientRegistrationRepository) {
        return new InMemoryReactiveOAuth2AuthorizedClientService(clientRegistrationRepository);
    }

    @Bean
    ReactiveOAuth2AuthorizedClientManager auth2AuthorizedClientManager(ReactiveOAuth2AuthorizedClientService service,
                                                                       ReactiveClientRegistrationRepository repository) {
        ReactiveOAuth2AuthorizedClientProvider provider = ReactiveOAuth2AuthorizedClientProviderBuilder
                .builder()
                .authorizationCode()
                .refreshToken()
                .build();
        ServerOAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository =
                new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(service);
        DefaultReactiveOAuth2AuthorizedClientManager clientManager =
                new DefaultReactiveOAuth2AuthorizedClientManager(repository, oAuth2AuthorizedClientRepository);
        clientManager.setAuthorizedClientProvider(provider);
        return clientManager;
    }

}
