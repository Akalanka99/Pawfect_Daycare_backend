package com.pawfectdaycare.pawfectdaycare.controller;

import com.pawfectdaycare.pawfectdaycare.dto.AssignStaffRequest;
import com.pawfectdaycare.pawfectdaycare.entity.User;
import com.pawfectdaycare.pawfectdaycare.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = "http://localhost:5173") // Allow React frontend
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping
    public ResponseEntity<List<User>> getAllUsers(){
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/assign/{id}")
    public ResponseEntity<String> assignStaff(@PathVariable String id) {
        AssignStaffRequest request = new AssignStaffRequest();
        request.setUuid(id);
        return ResponseEntity.ok(userService.assignStaff(request));
    }

}
