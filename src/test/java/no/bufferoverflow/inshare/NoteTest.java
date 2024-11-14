package no.bufferoverflow.inshare;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.vavr.collection.HashMap;

import java.time.Instant;
import java.util.UUID;

public class NoteTest {

    private Note originalNote;

    @BeforeEach
    public void setUp() {
        // Creating a sample note to use in tests
        originalNote = new Note(
                UUID.randomUUID(),
                new User(UUID.randomUUID(), "AuthorName", "AuthorPassword"),
                "Sample Note",
                Instant.now(),
                "Original Content",
                HashMap.empty()
        );
    }

    @Test
    public void testNewNoteSanitizesContent() {
        String maliciousContent = "<script>alert('XSS');</script><b>Bold Text</b>";

        // Create a new Note with potentially malicious content
        Note newNote = new Note(
                UUID.randomUUID(),
                new User(UUID.randomUUID(), "NewAuthor", "NewPassword"),
                "Malicious Note",
                Instant.now(),
                maliciousContent,
                HashMap.empty()
        );

        // Verify that the content is sanitized in the new note
        assertFalse(newNote.content.contains("<script>"), 
                    "Sanitized content should not contain <script> tags.");
        assertTrue(newNote.content.contains("<b>"), 
                   "Sanitized content should retain allowed <b> tags.");
    }

    @Test
    public void testWithContentSanitizesContent() {
        String maliciousContent = "<script>alert('XSS');</script><b>Bold Text</b>";

        // Update the original note's content using withContent and check sanitization
        Note updatedNote = originalNote.withContent(maliciousContent);

        assertNotEquals(originalNote.content, updatedNote.content, 
                        "Content should be updated and sanitized.");
        assertFalse(updatedNote.content.contains("<script>"), 
                    "Sanitized content should not contain <script> tags.");
        assertTrue(updatedNote.content.contains("<b>"), 
                   "Sanitized content should retain allowed <b> tags.");
    }
}
