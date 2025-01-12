package com.pawfectdaycare.pawfectdaycare.repository;

import com.pawfectdaycare.pawfectdaycare.entity.CageBooking;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CageBookingRepository extends JpaRepository<CageBooking, Long> {
}
