package com.pawfectdaycare.pawfectdaycare.service;

import com.pawfectdaycare.pawfectdaycare.entity.CageBooking;
import com.pawfectdaycare.pawfectdaycare.repository.CageBookingRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class CageBookingService {

    @Autowired
    private CageBookingRepository cageBookingRepository;

    public List<CageBooking> getAllCageBookings() {
        return cageBookingRepository.findAll();
    }

    public Optional<CageBooking> getCageBookingById(Long id) {
        return cageBookingRepository.findById(id);
    }
}
