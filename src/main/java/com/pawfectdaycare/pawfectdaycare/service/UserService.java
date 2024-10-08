package com.pawfectdaycare.pawfectdaycare.service;
import com.pawfectdaycare.pawfectdaycare.dto.RegisterRequest;
import com.pawfectdaycare.pawfectdaycare.entity.User;
import com.pawfectdaycare.pawfectdaycare.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public void registerUser(RegisterRequest registerRequest) {
        User user = new User(registerRequest.getName(),registerRequest.getEmail(), passwordEncoder.encode(registerRequest.getPassword()));
        userRepository.save(user);
    }
}