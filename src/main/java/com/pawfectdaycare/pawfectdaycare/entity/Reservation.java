package com.pawfectdaycare.pawfectdaycare.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;

@Getter
@Setter
@Entity
@Table(name = "booking")
public class Reservation {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String ownerName;
    private String email;
    private String homeAddress;
    private String phoneNumber;
    private String petCategory;
    private LocalDate fromDate;
    private LocalDate toDate;
    private String additionalCareDetails;

    // Default constructor for JPA
    public Reservation() {}

    // Constructor with parameters
    public Reservation(String ownerName, String email, String homeAddress, String phoneNumber, String petCategory,
                       LocalDate fromDate, LocalDate toDate, String additionalCareDetails) {
        this.ownerName = ownerName;
        this.email = email;
        this.homeAddress = homeAddress;
        this.phoneNumber = phoneNumber;
        this.petCategory = petCategory;
        this.fromDate = fromDate;
        this.toDate = toDate;
        this.additionalCareDetails = additionalCareDetails;
    }
}
