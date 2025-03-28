package com.pawfectdaycare.pawfectdaycare.repository;

import com.pawfectdaycare.pawfectdaycare.entity.Message;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface MessageRepository extends JpaRepository<Message, Long> {

    // Retrieve all messages sorted by latest createdAt
    List<Message> findByOrderByCreatedAtDesc();

    // Retrieve only unread messages, sorted by latest createdAt
    List<Message> findByIsReadFalseOrderByCreatedAtDesc();
}
