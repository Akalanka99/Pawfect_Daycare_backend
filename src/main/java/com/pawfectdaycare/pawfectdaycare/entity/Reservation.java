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
    private String homeaddress;
    private String phoneNumber;
    private String emergencyContact;
    private String petCategory;
    private String petName;
    private String petBreed;
    private String Age;
    private String additionalDetails;

    @ElementCollection
    @CollectionTable(name = "optional_grooming_services", joinColumns = @JoinColumn(name = "reservation_id"))
    @Column(name = "service")
    private List<String> optionalGroomingServices = new ArrayList<>();

    @OneToOne(cascade = CascadeType.ALL) // One-to-one relationship with BookingDetails
    @JoinColumn(name = "booking_details_id", referencedColumnName = "id")
    private BookingDetails bookingDetails;

    @OneToMany(mappedBy = "reservation", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<CageBooking> cageBookings = new ArrayList<>();

    // Add a utility method to manage the relationship
    public void addCageBooking(CageBooking cageBooking) {
        cageBookings.add(cageBooking);
        cageBooking.setReservation(this);
    }

    public void removeCageBooking(CageBooking cageBooking) {
        cageBookings.remove(cageBooking);
        cageBooking.setReservation(null);
    }


    // Default constructor for JPA
    public Reservation() {}

    // Constructor with parameters
    public Reservation(String ownerName, String email, String homeaddress, String phoneNumber,
                       String emergencyContact, String petCategory, String petName, String petBreed, String age,
                       String additionalDetails, List<String> optionalGroomingServices,
                       BookingDetails bookingDetails, List<CageBooking> cageBookings) {
        this.ownerName = ownerName;
        this.email = email;
        this.homeaddress = homeaddress;
        this.phoneNumber = phoneNumber;
        this.emergencyContact = emergencyContact;
        this.petCategory = petCategory;
        this.petName = petName;
        this.petBreed = petBreed;
        this.Age = age;
        this.bookingDetails = bookingDetails;
        this.additionalDetails= additionalDetails;
        this.cageBookings = cageBookings;
        this.optionalGroomingServices = optionalGroomingServices;

    }
}
