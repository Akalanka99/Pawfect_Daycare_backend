package com.pawfectdaycare.pawfectdaycare.service;

import com.pawfectdaycare.pawfectdaycare.entity.Message;
import com.pawfectdaycare.pawfectdaycare.repository.MessageRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class MessageService {
    @Autowired
    private MessageRepository messageRepository;

    public Message saveMessage(Message message) {
        return messageRepository.save(message);
    }

    public List<Message> getAllMessages() {
        return messageRepository.findByOrderByCreatedAtDesc();
    }

    public List<Message> getUnreadMessages() {
        return messageRepository.findByIsReadFalseOrderByCreatedAtDesc();
    }

    public Optional<Message> markMessageAsRead(Long id) {
        return messageRepository.findById(id)
                .map(message -> {
                    message.setRead(true);
                    return messageRepository.save(message);
                });
    }
}