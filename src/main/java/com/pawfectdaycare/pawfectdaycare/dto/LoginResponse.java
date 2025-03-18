package com.pawfectdaycare.pawfectdaycare.dto;

public class LoginResponse {

    private String token;

    private String role;

    public LoginResponse(String token, String role) {
        this.token = token;
        this.role = role;
    }

    // Getter
    public String getToken() {
        return token;
    }

    public String getRole() { return role; }

    public void setToken(String token) {
        this.token = token;
    }

    public void setRole(String role) { this.role = role; }
}
