
package com.pawfectdaycare.pawfectdaycare.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;

@Getter
@Setter
@Entity
@Table(name = "booking_details")
public class BookingDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

//    private LocalDate date; // For single-day bookings
    private LocalDate startDate; // For multi-day bookings
    private LocalDate endDate; // For multi-day bookings
    private boolean singleDay;
    private boolean multipleDay;


}
