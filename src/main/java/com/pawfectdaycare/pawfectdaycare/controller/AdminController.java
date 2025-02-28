package com.pawfectdaycare.pawfectdaycare.controller;

import com.pawfectdaycare.pawfectdaycare.dto.AssignStaffRequest;
import com.pawfectdaycare.pawfectdaycare.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
@CrossOrigin(origins = "http://localhost:5173")
public class AdminController {

    @Autowired
    UserService userService;

    @PostMapping("/assign-staff")
    public ResponseEntity<String> assignStaff(@RequestBody AssignStaffRequest request) {

        return ResponseEntity.ok(userService.assignStaff(request));
    }
}
