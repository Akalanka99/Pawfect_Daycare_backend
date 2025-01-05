
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

    private LocalDate date; // For single-day bookings
    private LocalDate startDate; // For multi-day bookings
    private LocalDate endDate; // For multi-day bookings
    private boolean isHalfDay;
    private boolean isMultipleDay;
    private String time; // Optional: if you need specific time information

    // Default constructor for JPA
    public BookingDetails() {}

    // Constructor with parameters
    public BookingDetails(LocalDate date, LocalDate startDate, LocalDate endDate, boolean isHalfDay,
                          boolean isMultipleDay, String time) {
        this.date = date;
        this.startDate = startDate;
        this.endDate = endDate;
        this.isHalfDay = isHalfDay;
        this.isMultipleDay = isMultipleDay;
        this.time = time;
    }
}
