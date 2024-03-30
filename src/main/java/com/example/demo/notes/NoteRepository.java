package com.example.demo.notes;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface NoteRepository extends JpaRepository<Note, Long> {
    //List<Note> getUserNotes(String username);
    List<Note> findByUserNotes(String username);

}

