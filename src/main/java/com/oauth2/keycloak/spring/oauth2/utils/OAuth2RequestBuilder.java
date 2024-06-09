package com.oauth2.keycloak.spring.oauth2.utils;

import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

public class OAuth2RequestBuilder {
    private String responseType;
    private String clientId;
    private String state;
    private String nonce;
    private String scope;
    private String codeChallenge;
    private String codeChallengeMethod;
    private String clientSecret;
    private String redirectUri;
    private String grantTypeRefresh;
    private String oldRefreshToken;
    private String grantType;
    private String codeVerifier;
    private String code;

    public OAuth2RequestBuilder withCode(String code) {
        this.code = code;
        return this;
    }

    public OAuth2RequestBuilder withCodeVerifier(String codeVerifier) {
        this.codeVerifier = codeVerifier;
        return this;
    }

    public OAuth2RequestBuilder withGrantType(String grantType) {
        this.grantType = grantType;
        return this;
    }

    public OAuth2RequestBuilder withGrantTypeRefresh(String grantTypeRefresh) {
        this.grantTypeRefresh = grantTypeRefresh;
        return this;
    }

    public OAuth2RequestBuilder withOldRefreshToken(String oldRefreshToken) {
        this.oldRefreshToken = oldRefreshToken;
        return this;
    }

    public OAuth2RequestBuilder withResponseType(String responseType) {
        this.responseType = responseType;
        return this;
    }

    public OAuth2RequestBuilder withClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public OAuth2RequestBuilder withState(String state) {
        this.state = state;
        return this;
    }

    public OAuth2RequestBuilder withNonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    public OAuth2RequestBuilder withScope(String scope) {
        this.scope = scope;
        return this;
    }

    public OAuth2RequestBuilder withCodeChallenge(String codeChallenge) {
        this.codeChallenge = codeChallenge;
        return this;
    }

    public OAuth2RequestBuilder withCodeChallengeMethod(String codeChallengeMethod) {
        this.codeChallengeMethod = codeChallengeMethod;
        return this;
    }

    public OAuth2RequestBuilder withClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    public OAuth2RequestBuilder withRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
        return this;
    }

    public MultiValueMap<String, String> build() {
        MultiValueMap<String, String> mapForm = new LinkedMultiValueMap<>();
        mapForm.add("response_type", responseType);
        mapForm.add("client_id", clientId);
        mapForm.add("state", state);
        mapForm.add("nonce", nonce);
        mapForm.add("scope", scope);
        mapForm.add("code_challenge", codeChallenge);
        mapForm.add("code_challenge_method", codeChallengeMethod);
        mapForm.add("client_secret", clientSecret);
        mapForm.add("redirect_uri", redirectUri);
        mapForm.add("grant_type_refresh", grantTypeRefresh);
        mapForm.add("old_refresh_token", oldRefreshToken);
        mapForm.add("grant_type", grantType);
        mapForm.add("code_verifier", codeVerifier);
        mapForm.add("code", code);
        return mapForm;
    }
}
