package com.oauth2.keycloak.spring.oauth2.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oauth2.keycloak.spring.oauth2.Dto.Oauth2Data;
import com.oauth2.keycloak.spring.oauth2.Dto.TokenRequest;
import com.oauth2.keycloak.spring.oauth2.utils.CookieUtils;
import com.oauth2.keycloak.spring.oauth2.utils.Helper;
import com.oauth2.keycloak.spring.oauth2.utils.OAuth2RequestBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@RestController
@RequestMapping("/bff")
public class BFFController {
    private Map<String, Oauth2Data> stateMap = new HashMap<>();

    public static final String IDTOKEN_COOKIE_KEY = "IT";
    public static final String REFRESHTOKEN_COOKIE_KEY = "RT";
    public static final String ACCESSTOKEN_COOKIE_KEY = "AT";
    public static final String S256 = "S256";
    public static final String RESPONSE_TYPE_CODE = "code";
    public static final String SCOPE = "openid";

    private final String clientSecret;
    private final String resourceServerURL;
    private final String keyCloakURI;
    private final String clientURL;
    private final String psbankUrl;
    private final String clientId;
    private final String grantTypeCode;
    private final String grantTypeRefresh;

    private final CookieUtils cookieUtils;
    private final Helper helper;
    private final RestTemplate restTemplate;

    @Autowired
    public BFFController(CookieUtils cookieUtils, Helper helper, RestTemplate restTemplate,
                         @Value("${keycloak.clientid}") String clientId, @Value("${keycloak.granttype.refresh}") String grantTypeRefresh,
                         @Value("${keycloak.granttype.code}") String grantTypeCode, @Value("${client.url}") String clientURL,
                         @Value("${keycloak.url}") String keyCloakURI, @Value("${resourceserver.url}") String resourceServerURL,
                         @Value("${keycloak.secret}") String clientSecret, @Value("${psbank.url}") String psbankUrl) {
        this.clientSecret = clientSecret;
        this.resourceServerURL = resourceServerURL;
        this.restTemplate = restTemplate;
        this.keyCloakURI = keyCloakURI;
        this.clientURL = clientURL;
        this.grantTypeCode = grantTypeCode;
        this.grantTypeRefresh = grantTypeRefresh;
        this.clientId = clientId;
        this.cookieUtils = cookieUtils;
        this.helper = helper;
        this.psbankUrl = psbankUrl;
    }

    @PostMapping("/generation")
    public HttpEntity<MultiValueMap<String, String>> dataGenerat(@RequestBody Oauth2Data oauth2Data) {
        if (!Objects.equals(oauth2Data.getClientId(), clientId)) {
            return ResponseEntity.badRequest().build();
        }
        String codeVerifier = helper.generateCodeVerifier();
        Oauth2Data data = new Oauth2Data();
        data.setState(oauth2Data.getState());
        data.setNonce(oauth2Data.getNonce());
        data.setCodeVerifier(codeVerifier);
        stateMap.put(oauth2Data.getState(), data);

        String codeChallenge = helper.generateCodeChallenge(codeVerifier);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> mapForm = new OAuth2RequestBuilder()
                .withResponseType(RESPONSE_TYPE_CODE)
                .withClientId(clientId)
                .withState(oauth2Data.getState())
                .withNonce(oauth2Data.getNonce())
                .withScope(SCOPE)
                .withCodeChallenge(codeChallenge)
                .withCodeChallengeMethod(S256)
                .withClientSecret(clientSecret)
                .withRedirectUri(psbankUrl)
                .build();

        return new HttpEntity<>(mapForm, headers);
    }

    @GetMapping("/data")
    public ResponseEntity<String> data(@CookieValue("AT") String accessToken) {

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(headers);

        return restTemplate.exchange(resourceServerURL+ "/user/data", HttpMethod.GET, request, String.class);
    }

    @GetMapping("/newAccessToken")
    public ResponseEntity<String> newAccessToken(@CookieValue("RT") String oldRefreshToken) {

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> mapForm = new OAuth2RequestBuilder()
                .withClientId(clientId)
                .withClientSecret(clientSecret)
                .withGrantTypeRefresh(grantTypeRefresh)
                .withOldRefreshToken(oldRefreshToken)
                .build();

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(mapForm, headers);

        ResponseEntity<String> response = restTemplate.exchange(keyCloakURI + "/token", HttpMethod.POST, request, String.class);

        try {

            HttpHeaders responseHeaders = createCookies(response);

            return ResponseEntity.ok().headers(responseHeaders).build();

        } catch (JsonProcessingException e) {
            e.printStackTrace();

        }
        return ResponseEntity.badRequest().build();
    }


    // удаление сессий пользователя внутри KeyCloak и также зануление всех куков
    @GetMapping("/logout")
    public ResponseEntity<String> logout(@CookieValue(IDTOKEN_COOKIE_KEY) String idToken) {

        String urlTemplate = UriComponentsBuilder.fromHttpUrl(keyCloakURI + "/logout")
                .queryParam("post_logout_redirect_uri", "{post_logout_redirect_uri}")
                .queryParam("id_token_hint", "{id_token_hint}")
                .queryParam("client_id", "{client_id}")
                .encode()
                .toUriString();

        Map<String, String> params = new HashMap<>();
        params.put("post_logout_redirect_uri", clientURL);
        params.put("id_token_hint", idToken);
        params.put("client_id", clientId);

        ResponseEntity<String> response = restTemplate.getForEntity(
                urlTemplate,
                String.class,
                params
        );


        if (response.getStatusCode() == HttpStatus.OK) {

            HttpHeaders responseHeaders = clearCookies();

            return ResponseEntity.ok().headers(responseHeaders).build();
        }

        return ResponseEntity.badRequest().build();
    }


    // получение access token от лица клиента
    @PostMapping("/token")
    public ResponseEntity<String> token(@RequestBody TokenRequest tokenRequest) {
        String authCode = tokenRequest.getAuthCode();
        String stateFromAuthServer = tokenRequest.getStateFromAuthServer();

        Oauth2Data data = stateMap.get(stateFromAuthServer);
        if (data != null) {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> mapForm = new OAuth2RequestBuilder()
                    .withGrantType(grantTypeCode)
                    .withClientId(clientId)
                    .withCodeVerifier(data.getCodeVerifier())
                    .withClientSecret(clientSecret)
                    .withCode(authCode)
                    .withRedirectUri(psbankUrl)
                    .build();

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(mapForm, headers);

            ResponseEntity<String> response = restTemplate.exchange(keyCloakURI + "/token", HttpMethod.POST, request, String.class);

            try {

                HttpHeaders responseHeaders = createCookies(response);

                HttpEntity<MultiValueMap<String, String>> request1 = new HttpEntity<>(mapForm, headers);

                return ResponseEntity.ok().headers(responseHeaders).build();


            } catch (JsonProcessingException e) {
                e.printStackTrace();

            }

            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.badRequest().build();
    }

    // создание куков для response
    private HttpHeaders createCookies(ResponseEntity<String> response) throws JsonProcessingException {

        ObjectMapper mapper = new ObjectMapper();

        JsonNode root = mapper.readTree(response.getBody());

        String accessToken = root.get("access_token").asText();
        String idToken = root.get("id_token").asText();
        String refreshToken = root.get("refresh_token").asText();

        int accessTokenDuration = root.get("expires_in").asInt();
        int refreshTokenDuration = root.get("refresh_expires_in").asInt();

        HttpCookie accessTokenCookie = cookieUtils.createCookie(ACCESSTOKEN_COOKIE_KEY, accessToken, accessTokenDuration);
        HttpCookie refreshTokenCookie = cookieUtils.createCookie(REFRESHTOKEN_COOKIE_KEY, refreshToken, refreshTokenDuration);
        HttpCookie idTokenCookie = cookieUtils.createCookie(IDTOKEN_COOKIE_KEY, idToken, accessTokenDuration);

        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        responseHeaders.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
        responseHeaders.add(HttpHeaders.SET_COOKIE, idTokenCookie.toString());

        return responseHeaders;
    }

    // зануляет все куки, чтобы браузер их удалил у себя
    private HttpHeaders clearCookies() {
        HttpCookie accessTokenCookie = cookieUtils.deleteCookie(ACCESSTOKEN_COOKIE_KEY);
        HttpCookie refreshTokenCookie = cookieUtils.deleteCookie(REFRESHTOKEN_COOKIE_KEY);
        HttpCookie idTokenCookie = cookieUtils.deleteCookie(IDTOKEN_COOKIE_KEY);

        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        responseHeaders.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
        responseHeaders.add(HttpHeaders.SET_COOKIE, idTokenCookie.toString());
        return responseHeaders;
    }

}
