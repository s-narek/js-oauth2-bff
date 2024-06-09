package com.oauth2.keycloak.spring.oauth2.Dto;

import lombok.Data;

@Data
public class TokenRequest {
    private String authCode;
    private String stateFromAuthServer;
}
