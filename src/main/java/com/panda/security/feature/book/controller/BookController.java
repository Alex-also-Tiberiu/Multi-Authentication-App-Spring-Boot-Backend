package com.panda.security.feature.book.controller;

import com.panda.security.feature.book.dto.BookRequest;
import com.panda.security.feature.book.entity.Book;
import com.panda.security.feature.book.service.BookService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/books")
@RequiredArgsConstructor
public class BookController {

    @Autowired
    private BookService service;

    @PostMapping
    public ResponseEntity<?> save(@RequestBody BookRequest request) {
        service.save(request);
        return ResponseEntity.accepted().build();
    }

    @GetMapping
    public ResponseEntity<List<Book>> findAllBooks() {
        return ResponseEntity.ok(service.findAll());
    }
}

