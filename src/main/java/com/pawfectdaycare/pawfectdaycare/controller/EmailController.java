package com.pawfectdaycare.pawfectdaycare.controller;

import com.pawfectdaycare.pawfectdaycare.dto.EmailRequest;
import com.pawfectdaycare.pawfectdaycare.service.EmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/emails") // Update the base URL to reflect the new controller name
@CrossOrigin(origins = {"http://localhost:3000", "http://localhost:5173"}, allowedHeaders = "*")
public class EmailController {

    @Autowired
    private EmailService emailService;

    @PostMapping("/reply")
    public ResponseEntity<String> replyToCustomer(@RequestBody EmailRequest replyRequest) {
        System.out.println("Email: =================" + replyRequest.getEmail());
        System.out.println("Message: ===========================================" + replyRequest.getMessage());
        try {
            emailService.sendEmail(
                    replyRequest.getEmail(),
                    "Reply from Pawfect Daycare",
                    replyRequest.getMessage()
            );
            return ResponseEntity.ok("Reply sent successfully.");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("Failed to send reply.");
        }
    }
}