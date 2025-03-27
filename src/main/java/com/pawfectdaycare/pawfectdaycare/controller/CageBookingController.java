package com.pawfectdaycare.pawfectdaycare.controller;

import com.pawfectdaycare.pawfectdaycare.entity.CageBooking;
import com.pawfectdaycare.pawfectdaycare.service.CageBookingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/cage-bookings")
@CrossOrigin(origins = "http://localhost:5173")
public class CageBookingController {

    @Autowired
    private CageBookingService cageBookingService;

    @GetMapping("/availability")
    public ResponseEntity<?> checkAvailability(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date) {
        return ResponseEntity.ok(cageBookingService.getCageAvailabilityForDate(date));
    }
    
    @GetMapping("/availability/range")
    public ResponseEntity<?> checkAvailabilityForRange(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate) {
        return ResponseEntity.ok(cageBookingService.getCageAvailabilityForDateRange(startDate, endDate));
    }

    // Fetch all bookings
    @GetMapping
    public List<CageBooking> getAllBookings() {
        return cageBookingService.getAllBookings();
    }

    // Fetch bookings by date
    @GetMapping("/date/{date}")
    public List<CageBooking> getBookingsByDate(@PathVariable String date) {
        LocalDate parsedDate = LocalDate.parse(date);
        return cageBookingService.getBookingsByDate(parsedDate);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteCageBooking(@PathVariable Long id) {
        cageBookingService.deleteCageBooking(id); // Use the instance, not the class name
        return ResponseEntity.noContent().build();
    }


}