package com.oauth2.keycloak.spring.oauth2.Dto;

import lombok.Data;

@Data
public class Oauth2Data {
    private String state;
    private String nonce;
    private String clientId;
    private String redirectUri;
    private String codeVerifier;
}
