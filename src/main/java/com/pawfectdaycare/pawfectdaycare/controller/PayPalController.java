package com.pawfectdaycare.pawfectdaycare.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api/paypal")
public class PayPalController {

    @Value("${paypal.client-id}")
    private String clientId;

    @Value("${paypal.client-secret}")
    private String clientSecret;

    private final String PAYPAL_BASE_URL = "https://api-m.sandbox.paypal.com";

    /**
     * Generate PayPal Access Token
     */
    private String getAccessToken() {
        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth(clientId, clientSecret);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<String> entity = new HttpEntity<>("grant_type=client_credentials", headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                PAYPAL_BASE_URL + "/v1/oauth2/token",
                HttpMethod.POST,
                entity,
                Map.class
        );

        return response.getBody().get("access_token").toString();
    }

    /**
     * Create PayPal Order
     */
    @PostMapping("/create-order")
    public ResponseEntity<?> createOrder(@RequestBody Map<String, Object> request) {
        String accessToken = getAccessToken();

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);

        String requestBody = "{"
                + "\"intent\":\"CAPTURE\","
                + "\"purchase_units\":[{\"amount\":{\"currency_code\":\"USD\",\"value\":\"" + request.get("amount") + "\"}}],"
                + "\"application_context\":{"
                + "\"return_url\":\"http://localhost:3000/success\","
                + "\"cancel_url\":\"http://localhost:3000/cancel\""
                + "}"
                + "}";

        HttpEntity<String> entity = new HttpEntity<>(requestBody, headers);
        RestTemplate restTemplate = new RestTemplate();

        ResponseEntity<Map> response = restTemplate.exchange(
                PAYPAL_BASE_URL + "/v2/checkout/orders",
                HttpMethod.POST,
                entity,
                Map.class
        );

        return ResponseEntity.ok(response.getBody());
    }

    /**
     * Capture PayPal Payment
     */
    @PostMapping("/capture-payment/{orderId}")
    public ResponseEntity<?> capturePayment(@PathVariable String orderId) {
        String accessToken = getAccessToken();

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> entity = new HttpEntity<>("", headers);
        RestTemplate restTemplate = new RestTemplate();

        ResponseEntity<Map> response = restTemplate.exchange(
                PAYPAL_BASE_URL + "/v2/checkout/orders/" + orderId + "/capture",
                HttpMethod.POST, entity, Map.class
        );

        return ResponseEntity.ok(response.getBody());
    }
}
