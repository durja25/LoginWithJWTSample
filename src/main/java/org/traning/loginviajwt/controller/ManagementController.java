package org.traning.loginviajwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/management")
public class ManagementController {


    @GetMapping
    public ResponseEntity<String> get() {
        return ResponseEntity.ok("GET: /api/v1/management");
    }

    @PostMapping
    public ResponseEntity<String> post() {
        return ResponseEntity.ok("post: /api/v1/management");
    }

    @PutMapping
    public ResponseEntity<String> put() {
        return ResponseEntity.ok("Put: /api/v1/management");
    }

    @DeleteMapping
    public ResponseEntity<String> delete() {
        return ResponseEntity.ok("delete: /api/v1/management");
    }


}
