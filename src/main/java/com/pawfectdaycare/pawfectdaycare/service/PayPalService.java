package com.pawfectdaycare.pawfectdaycare.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.*;

import java.util.Base64;
import java.util.Map;

@Service
public class PayPalService {
    @Value("${paypal.client-id}")
    private String clientId;

    @Value("${paypal.client-secret}")
    private String clientSecret;

    private static final String PAYPAL_API_BASE = "https://api-m.sandbox.paypal.com";

    public String getAccessToken() {
        RestTemplate restTemplate = new RestTemplate();
        String auth = clientId + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic " + encodedAuth);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<String> entity = new HttpEntity<>("grant_type=client_credentials", headers);
        ResponseEntity<Map> response = restTemplate.exchange(PAYPAL_API_BASE + "/v1/oauth2/token", HttpMethod.POST, entity, Map.class);

        return response.getBody().get("access_token").toString();
    }
}

