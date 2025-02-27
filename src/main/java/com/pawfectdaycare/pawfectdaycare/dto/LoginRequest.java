package com.pawfectdaycare.pawfectdaycare.dto;

import lombok.Getter;
import lombok.Setter;

public class LoginRequest {

    // Getters and Setters
    @Setter
    @Getter
    private String email;
    private String password;

}
