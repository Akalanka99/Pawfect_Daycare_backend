package com.pawfectdaycare.pawfectdaycare.service;

import com.pawfectdaycare.pawfectdaycare.entity.BookingDetails;
import com.pawfectdaycare.pawfectdaycare.entity.CageBooking;
import com.pawfectdaycare.pawfectdaycare.entity.Reservation;
import com.pawfectdaycare.pawfectdaycare.repository.CageBookingRepository;
import com.pawfectdaycare.pawfectdaycare.repository.ReservationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class ReservationService {

    @Autowired
    private ReservationRepository reservationRepository;

    @Autowired
    private CageBookingRepository cageBookingRepository;

    // Save or update a reservation with date handling
    @Transactional
    public Reservation saveReservation(Reservation reservation) {
        // Get the booking details
        BookingDetails bookingDetails = reservation.getBookingDetails();
        LocalDate startDate = bookingDetails.getStartDate();
        LocalDate endDate = bookingDetails.getEndDate();
        
        // Check if we're dealing with a multi-day booking
        boolean isMultiDayBooking = bookingDetails.isMultipleDay();
        
        // Create a list to hold all the cage bookings
        List<CageBooking> allCageBookings = new ArrayList<>();
        
        // Process each selected cage
        for (CageBooking cageBooking : reservation.getCageBookings()) {
            // For single-day bookings
            if (!isMultiDayBooking || startDate.equals(endDate)) {
                // Set the booking date
                cageBooking.setBookingDate(startDate);
                cageBooking.setReservation(reservation);
                allCageBookings.add(cageBooking);
            } else {
                // For multi-day bookings, create a booking for each day in the range
                LocalDate currentDate = startDate;
                while (!currentDate.isAfter(endDate)) {
                    CageBooking dailyBooking = new CageBooking();
                    dailyBooking.setCageId(cageBooking.getCageId());
                    dailyBooking.setMorning(cageBooking.isMorning());
                    dailyBooking.setAfternoon(cageBooking.isAfternoon());
                    dailyBooking.setBookingDate(currentDate);
                    dailyBooking.setReservation(reservation);
                    allCageBookings.add(dailyBooking);
                    
                    currentDate = currentDate.plusDays(1);
                }
            }
        }
        
        // Clear and replace all cage bookings
        reservation.getCageBookings().clear();
        reservation.getCageBookings().addAll(allCageBookings);
        
        // Save the reservation
        return reservationRepository.save(reservation);
    }

    // Get reservation by ID
    public Optional<Reservation> getReservationById(Long id) {
        return reservationRepository.findById(id);
    }
}