package com.cashigo.gateway.consts;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "keycloak")
@Component
@Data
public class ClientConstants {

    public String clientRegistrationId;
    public String clientId;
    public String clientSecret;
    public String authorizationUri;
    public String redirectUri;
    public String tokenUri;
    public String jwkSetUri;
    public String userInfoUri;
    public String userNameAttributeName;
    public String issuerUri;


}
