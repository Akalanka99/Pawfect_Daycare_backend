package com.pawfectdaycare.pawfectdaycare.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.Base64;
import java.util.Map;

@Service
public class PayPalService {

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private com.pawfectdaycare.pawfectdaycare.config.PayPalConfig payPalConfig;

    private String getAccessToken() {
        String credentials = payPalConfig.getClientId() + ":" + payPalConfig.getClientSecret();
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic " + encodedCredentials);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<String> entity = new HttpEntity<>("grant_type=client_credentials", headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                payPalConfig.getBaseUrl() + "/v1/oauth2/token",
                HttpMethod.POST, entity, Map.class
        );

        return response.getBody().get("access_token").toString();
    }

    public String createOrder(String amount) {
        String accessToken = getAccessToken();

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> requestBody = Map.of(
                "intent", "CAPTURE",
                "purchase_units", new Object[] {
                        Map.of(
                                "amount", Map.of(
                                        "currency_code", "USD",
                                        "value", amount
                                )
                        )
                },
                "application_context", Map.of(
                        "return_url", "http://localhost:3000/success",
                        "cancel_url", "http://localhost:3000/cancel"
                )
        );

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(
                payPalConfig.getBaseUrl() + "/v2/checkout/orders",
                entity, Map.class
        );

        return response.getBody().get("id").toString();
    }
}
