package no.bufferoverflow.inshare;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import java.util.UUID;
import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

class UserTest {

    @Mock
    private JdbcTemplate jdbcTemplate;

    private User testUser;

    @BeforeEach
    void setUp() {
        jdbcTemplate = mock(JdbcTemplate.class);
        // Initialize the test User object
        testUser = new User(UUID.randomUUID(), "testuser", "hashed_password");
    }

    @Test
    @SuppressWarnings("unchecked") // Suppress the unchecked warning for the query call
    void loadReadableNotes_shouldUseParameterizedQuery() {
        // Arrange: Mock the response for the query
        when(jdbcTemplate.query(any(String.class), any(RowMapper.class), any(Object.class)))
                .thenReturn(Collections.emptyList()); // Mock returning an empty set

        // Act: Call the method
        testUser.loadReadableNotes(jdbcTemplate);

        // Assert: Verify that query() is called with a parameterized SQL and that the username is passed as a parameter
        verify(jdbcTemplate).query(
            eq("""
                SELECT n.id, n.name, n.created, n.content, u.username, a.id AS author_id, a.username AS author_username, a.password AS author_password
                FROM Note n
                JOIN NoteUserRoles nur ON n.id = nur.note
                JOIN RolePermissions rp ON nur.role = rp.role
                JOIN User u ON nur.user = u.id
                JOIN User a ON n.author = a.id
                WHERE u.username = ? AND rp.permission = 'READ'
                """),
            any(RowMapper.class), // Cast the RowMapper to avoid the generic type warning
            eq("testuser") // Confirm that 'testuser' is passed as a parameter, not concatenated
        );
    }
}

