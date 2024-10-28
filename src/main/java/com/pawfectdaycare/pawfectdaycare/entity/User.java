package com.pawfectdaycare.pawfectdaycare.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Entity
@Table(name = "users")

public class User {

    // Getters and Setters
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String email;

    private String password;

    public User() {}

    public User(String name,String email, String password) {
        this.name = name;
        this.email = email;
        this.password = password;

    }

}
