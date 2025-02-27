package com.pawfectdaycare.pawfectdaycare.controller;

import com.google.firebase.auth.FirebaseToken;
import com.pawfectdaycare.pawfectdaycare.entity.User;
import com.pawfectdaycare.pawfectdaycare.repository.UserRepository;
import com.pawfectdaycare.pawfectdaycare.service.FirebaseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:5173") // ✅ Allow frontend access
public class AuthController {

    @Autowired
    private FirebaseService firebaseService;

    @Autowired
    private UserRepository userRepository;

    @PostMapping("/verify-token")
    public Map<String, String> verifyToken(@RequestBody Map<String, String> request) {
        String idToken = request.get("token");
        Map<String, String> response = new HashMap<>();

        try {
            FirebaseToken decodedToken = firebaseService.verifyToken(idToken);
            String uid = decodedToken.getUid();
            String email = decodedToken.getEmail();
            String displayName = decodedToken.getName();

            System.out.println("haaaaaaaa"+uid+ email+ displayName);

            // Check if user already exists
            User user = userRepository.findByUid(uid);
            if (user == null) {
                /////////////////////////////////////////////////////lllllllllooookkk
                user = new User(uid, displayName, email);
                userRepository.save(user);
            }

            response.put("status", "success");
            response.put("uid", uid);
            response.put("email", email);
            response.put("displayName", displayName);
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
        }

        return response;
    }
}
