package com.pawfectdaycare.pawfectdaycare.service;

import com.pawfectdaycare.pawfectdaycare.entity.CageBooking;
import com.pawfectdaycare.pawfectdaycare.repository.CageBookingRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.*;

@Service
public class CageBookingService {

    @Autowired
    private CageBookingRepository cageBookingRepository;

    private static final int TOTAL_CAGES = 10; // Total number of cages available

     // Add this method to get a cage booking by ID
    public Optional<CageBooking> getCageBookingById(Long id) {
        return cageBookingRepository.findById(id);
    }
    public List<Map<String, Object>> getCageAvailabilityForDate(LocalDate date) {
        List<CageBooking> bookings = cageBookingRepository.findByBookingDate(date);

        // Create a map of cage IDs to their bookings
        Map<Long, CageBooking> bookedCages = new HashMap<>();
        for (CageBooking booking : bookings) {
            bookedCages.put(booking.getCageId(), booking);
        }

        List<Map<String, Object>> result = new ArrayList<>();

        // Generate availability data for all cages
        for (int i = 1; i <= TOTAL_CAGES; i++) {
            Long cageId = (long) i;
            Map<String, Object> cageData = new HashMap<>();
            cageData.put("id", cageId);

            if (bookedCages.containsKey(cageId)) {
                CageBooking booking = bookedCages.get(cageId);
                cageData.put("morning", !booking.isMorning()); // true means available
                cageData.put("afternoon", !booking.isAfternoon());
            } else {
                cageData.put("morning", true);
                cageData.put("afternoon", true);
            }

            result.add(cageData);
        }

        return result;
    }

    public Map<String, List<Map<String, Object>>> getCageAvailabilityForDateRange(
            LocalDate startDate, LocalDate endDate) {

        Map<String, List<Map<String, Object>>> result = new HashMap<>();

        LocalDate current = startDate;
        while (!current.isAfter(endDate)) {
            result.put(current.toString(), getCageAvailabilityForDate(current));
            current = current.plusDays(1);
        }

        return result;
    }
    public List<CageBooking> getAllBookings() {
        return cageBookingRepository.findAll();
    }

    public List<CageBooking> getBookingsByDate(LocalDate date) {
        return cageBookingRepository.findByBookingDate(date);
    }
}
