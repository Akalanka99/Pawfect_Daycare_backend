package com.pawfectdaycare.pawfectdaycare.controller;

import com.pawfectdaycare.pawfectdaycare.entity.CageBooking;
import com.pawfectdaycare.pawfectdaycare.entity.Reservation;
import com.pawfectdaycare.pawfectdaycare.service.CageBookingService;
import com.pawfectdaycare.pawfectdaycare.service.ReservationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/reservations")
@CrossOrigin(origins = "http://localhost:5173") // Allow React frontend
public class ReservationController {

    @Autowired
    private ReservationService reservationService;

    @Autowired
    private CageBookingService cageBookingService; // Inject CageBookingService instance

    @PostMapping
    public ResponseEntity<Reservation> createReservation(@RequestBody Reservation reservation) {
        // Save the reservation along with its associated CageBooking entities
        Reservation createdReservation = reservationService.saveReservation(reservation);

        System.out.println("Saved Reservation Data: " + createdReservation);

        // Return the saved reservation in the response
        return ResponseEntity.status(HttpStatus.CREATED).body(createdReservation);
    }


    @GetMapping("/cage/{id}")
    public ResponseEntity<CageBooking> getCageBookingById(@PathVariable Long id) {
        // Use the injected instance of CageBookingService
        return cageBookingService.getCageBookingById(id)
                .map(cageBooking -> ResponseEntity.ok(cageBooking))
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }



}