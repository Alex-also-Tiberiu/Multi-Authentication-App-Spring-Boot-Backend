package com.panda.security.feature.book.repository;

import com.panda.security.feature.book.entity.Book;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BookRepository extends JpaRepository<Book, Integer> {
}

