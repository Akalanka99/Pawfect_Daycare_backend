package com.pawfectdaycare.pawfectdaycare.service;

import com.pawfectdaycare.pawfectdaycare.entity.CageBooking;
import com.pawfectdaycare.pawfectdaycare.entity.Reservation;
import com.pawfectdaycare.pawfectdaycare.repository.CageBookingRepository;
import com.pawfectdaycare.pawfectdaycare.repository.ReservationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class ReservationService {

    @Autowired
    private ReservationRepository reservationRepository;

    @Autowired
    private CageBookingRepository cageBookingRepository;

    // Save or update a reservation
    public Reservation saveReservation(Reservation reservation) {
        for (CageBooking cageBooking : reservation.getCageBookings()) {
            cageBooking.setReservation(reservation); // Set the relationship
        }
        return reservationRepository.save(reservation);
    }


    // Get reservation by ID
    public Optional<Reservation> getReservationById(Long id) {
        return reservationRepository.findById(id);
    }

    // Update cage bookings
    public void updateCageBookings(Long reservationId, CageBooking newCageBooking) {
        Optional<Reservation> reservationOpt = reservationRepository.findById(reservationId);
        if (reservationOpt.isPresent()) {
            Reservation reservation = reservationOpt.get();
            reservation.addCageBooking(newCageBooking);
            reservationRepository.save(reservation);
        } else {
            throw new IllegalArgumentException("Reservation not found for ID: " + reservationId);
        }
    }
}
