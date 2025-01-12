package com.pawfectdaycare.pawfectdaycare.entity;

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
    @JoinColumn(name = "reservation_id", nullable = false)
    private Reservation reservation;

    private Long cageId;
    private boolean morning;
    private boolean afternoon;
    private LocalDate startDate; // For multi-day bookings
    private LocalDate endDate;

    public CageBooking() {}

    public CageBooking(Long cageId, boolean morning, boolean afternoon,LocalDate startDate,LocalDate endDate) {
        this.cageId = cageId;
        this.morning = morning;
        this.afternoon = afternoon;
        this.startDate = startDate;
        this.endDate = endDate;
    }

    @Override
    public String toString() {
        return "CageBooking{" +
                "id=" + id +
                ", cageId=" + cageId +
                ", morning=" + morning +
                ", afternoon=" + afternoon +
                ", startDate=" + startDate +
                ", endDate=" + endDate +
                '}';
    }
}
