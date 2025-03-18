package com.pawfectdaycare.pawfectdaycare.service;
import com.pawfectdaycare.pawfectdaycare.dto.AssignStaffRequest;
import com.pawfectdaycare.pawfectdaycare.dto.RegisterRequest;
import com.pawfectdaycare.pawfectdaycare.entity.User;
import com.pawfectdaycare.pawfectdaycare.entity.Role;
import com.pawfectdaycare.pawfectdaycare.entity.User;
import com.pawfectdaycare.pawfectdaycare.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public void registerUser(RegisterRequest registerRequest) {
        User user = new User(registerRequest.getName(),registerRequest.getEmail(), passwordEncoder.encode(registerRequest.getPassword()), registerRequest.getRole());
        userRepository.save(user);
    }

   public String assignStaff(AssignStaffRequest assignStaffRequest) {
        User existUser = userRepository.findByUid(assignStaffRequest.getUuid());

        if(existUser != null) {
            existUser.setRole(Role.STAFF);
            userRepository.save(existUser);
            return "User assign as a staff";

        } else {
            return "User doesn't exists";
        }
   }



    // Get all users
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    // Get a user by ID
    public Optional<User> getUserById(Long id) {
        return userRepository.findById(id);
    }

    // Update a user
    public User updateUser(Long id, User userDetails) {
        return userRepository.findById(id).map(user -> {
            user.setName(userDetails.getName());
            return userRepository.save(user);
        }).orElseThrow(() -> new RuntimeException("User not found"));
    }

    // Delete a user
    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }
}