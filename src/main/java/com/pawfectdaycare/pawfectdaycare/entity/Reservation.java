package com.pawfectdaycare.pawfectdaycare.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.util.List;
import java.util.ArrayList;



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
    private String emergencyContact;
    private String petCategory;
    private String petName;
    private String petBreed;
    private String Age;


    @OneToOne(cascade = CascadeType.ALL) // One-to-one relationship with BookingDetails
    @JoinColumn(name = "booking_details_id", referencedColumnName = "id")
    private BookingDetails bookingDetails;

    @OneToMany(mappedBy = "reservation", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<CageBooking> cageBookings = new ArrayList<>();




    // Default constructor for JPA
    public Reservation() {}

    // Constructor with parameters
    public Reservation(String ownerName, String email, String homeAddress, String phoneNumber,
                       String emergencyContact, String petCategory, String petName, String petBreed, String age,
                       BookingDetails bookingDetails) {
        this.ownerName = ownerName;
        this.email = email;
        this.homeAddress = homeAddress;
        this.phoneNumber = phoneNumber;
        this.emergencyContact = emergencyContact;
        this.petCategory = petCategory;
        this.petName = petName;
        this.petBreed = petBreed;
        this.Age = age;
        this.bookingDetails = bookingDetails;

    }
}
