package com.pawfectdaycare.pawfectdaycare.seeders;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.UserRecord;
import com.pawfectdaycare.pawfectdaycare.entity.Role;
import com.pawfectdaycare.pawfectdaycare.entity.User;
import com.pawfectdaycare.pawfectdaycare.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class InitialSeeder implements ApplicationListener<ApplicationReadyEvent> {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        try {
            String adminEmail = "admin@gmail.com";
            userRepository.findByEmail(adminEmail)
                    .ifPresentOrElse(
                            user -> System.out.println("✅ Admin already exists in DB"),
                            () -> createFirebaseAdmin(adminEmail)
                    );
        } catch (Exception e) {
            System.err.println("❌ Error creating admin: " + e.getMessage());
        }
    }

    private void createFirebaseAdmin(String email) {
        try {
            // Check if user exists in Firebase
            UserRecord userRecord;
            try {
                userRecord = FirebaseAuth.getInstance().getUserByEmail(email);
                System.out.println("✅ Admin already exists in Firebase: " + userRecord.getUid());
            } catch (Exception e) {
                // If user doesn't exist, create one
                UserRecord.CreateRequest request = new UserRecord.CreateRequest()
                        .setEmail(email)
                        .setPassword("admin123") // Set a strong password
                        .setDisplayName("Admin")
                        .setEmailVerified(true);

                userRecord = FirebaseAuth.getInstance().createUser(request);
                System.out.println("✅ Admin created in Firebase: " + userRecord.getUid());
            }

            // Save admin in local database
            User admin = new User(userRecord.getUid(), "Admin", email, passwordEncoder.encode("admin123"), Role.ADMIN);
            userRepository.save(admin);
            System.out.println("✅ Admin saved in local DB");

        } catch (Exception e) {
            System.err.println("❌ Error creating admin in Firebase: " + e.getMessage());
        }
    }
}
