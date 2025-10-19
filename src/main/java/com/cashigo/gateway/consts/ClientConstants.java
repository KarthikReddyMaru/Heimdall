package com.cashigo.gateway.consts;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "keycloak")
@Component
@Data
public class ClientConstants {

    private String clientRegistrationId;
    private String clientId;
    private String clientSecret;
    private String authorizationUri;
    private String redirectUri;
    private String tokenUri;
    private String jwkSetUri;
    private String userInfoUri;
    private String userNameAttributeName;
    private String issuerUri;


}
