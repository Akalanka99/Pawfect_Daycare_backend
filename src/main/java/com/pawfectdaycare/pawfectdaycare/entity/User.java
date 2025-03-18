package com.pawfectdaycare.pawfectdaycare.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String uid; // Firebase UID
    private String name; // Display name

    private String uid; // Firebase UID
    private String name; // Display name
    private String email;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    // Constructors
    @Enumerated(EnumType.STRING)
    private Role role;

    // Constructors
    public User() {}

    // Constructor with uid
    public User(String uid, String name, String email, String password, Role role) {
        this.uid = uid;
    // Constructor with uid
    public User(String uid, String name, String email, String password, Role role) {
        this.uid = uid;
        this.name = name;
        this.email = email;
        this.password = password;
        this.role = role;
    }

    // Constructor without uid (for manual user registration)
    public User(String name, String email, String password, Role role) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.role = role;
        this.role = role;
    }

    // Constructor without uid (for manual user registration)
    public User(String name, String email, String password, Role role) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.role = role;
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUid() {
        return uid;
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public String getUid() {
        return uid;
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {  // Add getter for password
    public String getPassword() {  // Add getter for password
        return password;
    }

    public void setPassword(String password) {  // Add setter for password
    public void setPassword(String password) {  // Add setter for password
        this.password = password;
    }

    public Role getRole() { return role; }

    public void setRole(Role role) { this.role = role; }

    public Role getRole() { return role; }

    public void setRole(Role role) { this.role = role; }
}
