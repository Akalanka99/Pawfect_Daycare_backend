package com.pawfectdaycare.pawfectdaycare.repository;

import com.pawfectdaycare.pawfectdaycare.entity.CageBooking;

import java.time.LocalDate;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CageBookingRepository extends JpaRepository<CageBooking, Long> {
    // Find all bookings for a specific date
    List<CageBooking> findByBookingDate(LocalDate date);

    // Find all bookings for a specific cage on a specific date
    List<CageBooking> findByCageIdAndBookingDate(Long cageId, LocalDate date);

    // Find all bookings for a date range (for multi-day bookings)
    List<CageBooking> findByCageIdAndBookingDateBetween(Long cageId, LocalDate startDate, LocalDate endDate);
}
