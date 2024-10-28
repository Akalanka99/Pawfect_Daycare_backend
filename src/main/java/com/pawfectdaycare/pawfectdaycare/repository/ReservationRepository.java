package com.pawfectdaycare.pawfectdaycare.repository;


import com.pawfectdaycare.pawfectdaycare.entity.Reservation;
import org.springframework.data.jpa.repository.JpaRepository;


public interface ReservationRepository extends JpaRepository<Reservation, Long> {
}
