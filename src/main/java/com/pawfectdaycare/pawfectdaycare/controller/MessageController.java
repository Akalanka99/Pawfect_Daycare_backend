package com.pawfectdaycare.pawfectdaycare.controller;

import com.pawfectdaycare.pawfectdaycare.entity.Message;
import com.pawfectdaycare.pawfectdaycare.service.MessageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/messages")
@CrossOrigin(origins = {"http://localhost:3000", "http://localhost:5173"}, allowedHeaders = "*")
public class MessageController {
    @Autowired
    private MessageService messageService;

    @PostMapping("/sendmessage")
    public ResponseEntity<?> submitMessage(@RequestBody Message message) {
        try {
            // Save the message
            Message savedMessage = messageService.saveMessage(message);
            return ResponseEntity.ok(savedMessage);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error saving message: " + e.getMessage());
        }
    }


    @GetMapping("/getmessages")
    public ResponseEntity<List<Message>> getAllMessages() {
        return ResponseEntity.ok(messageService.getAllMessages());
    }

    @GetMapping("/unread")
    public ResponseEntity<List<Message>> getUnreadMessages() {
        return ResponseEntity.ok(messageService.getUnreadMessages());
    }

    @PutMapping("/{id}/read")
    public ResponseEntity<Message> markMessageAsRead(@PathVariable Long id) {
        return messageService.markMessageAsRead(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}