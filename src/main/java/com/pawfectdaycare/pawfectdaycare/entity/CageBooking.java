package com.pawfectdaycare.pawfectdaycare.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;

@Getter
@Setter
@Entity
@Table(name = "cage_bookings")
public class CageBooking {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne // Many cage bookings can belong to one reservation
    @JsonIgnore
    @JoinColumn(name = "reservation_id", nullable = false)
    private Reservation reservation;

    private Long cageId;
    private boolean morning;
    private boolean afternoon;
    private LocalDate bookingDate;

    public CageBooking() {}

    public CageBooking(Long cageId, boolean morning, boolean afternoon,LocalDate bookingDate) {
        this.cageId = cageId;
        this.morning = morning;
        this.afternoon = afternoon;
        this.bookingDate = bookingDate;
    }

}
