package com.oauth2.keycloak.spring.oauth2.dto;

import lombok.Data;

@Data
public class TokenRequest {
    private String authCode;
    private String stateFromAuthServer;
}
