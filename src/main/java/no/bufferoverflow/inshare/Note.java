package no.bufferoverflow.inshare;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.vavr.Tuple2;
import io.vavr.collection.HashMap;
import io.vavr.collection.Map;
import io.vavr.collection.Set;
import io.vavr.collection.HashSet;
import io.ebean.uuidv7.UUIDv7;
import org.springframework.jdbc.core.JdbcTemplate;
import java.time.Instant;

import java.util.UUID;
import java.util.Comparator;

import org.owasp.validator.html.*;
import java.io.IOException;
import java.io.InputStream;

/**
 * Represents a Note in the InShare application.
 * A Note is defined by an ID, name, creation timestamp, content,
 * and a map of user roles.
 */
public final class Note {
    public final UUID id;
    public final User author;
    public final String name;
    public final Instant created;
    public final String content;
    private static final Logger logger = LoggerFactory.getLogger(Note.class);

    /**
     * A map representing the roles assigned to users.
     * The key is the user ID, and the value the role for
     * the user with that ID.
     */
    public final Map<UUID, Role> userRoles;


    /**
     * Comparator for comparing notes by their creation date.
     */
    public static final Comparator<Note> byCreationDate = new Comparator<Note> (){

        @Override
        public int compare(Note note0, Note note1) {
            return note0.created.compareTo(note1.created);
        }

    };

    /**
     * Enum representing possible permissions for a note.
     */
    public static enum Permission {
        READ, WRITE, DELETE
    }

    /**
     * Enum representing possible roles for a note.
     */
    public static enum Role {
        OWNER, ADMINISTRATOR, EDITOR, READER
    }

    /**
     * Constructor for Note which sets all its data.
     *
     * @param id The unique identifier of the note.
     * @param name The name of the note.
     * @param created The timestamp when the note was created.
     * @param content The content of the note.
     * @param userRoles The map of user roles for this note.
     */
    public Note(UUID id, User author, String name, Instant created, String content, Map<UUID, Role> userRoles) {
        this.id = id;
        this.name = name;
        this.author = author;
        this.created = created;
        this.content = sanitizedContent(content);
        this.userRoles = userRoles;
    }

    /**
     * Constructs a new Note with a generated ID and current timestamp.
     * The note is created without any permissions.
     *
     * @param name The name of the note.
     * @param content The content of the note.
     */
    public Note(User author, String name, String content) {
        this(UUIDv7.generate()
            , author
            , name
            , Instant.now()
            , content
            , HashMap.empty());
    }

    /**
     * Returns a new Note object with updated name.
     *
     * @param name The new name for the note.
     * @return A new Note instance with the updated name.
     */
    public Note withName(String name) { 
        return new Note(this.id, this.author, name, this.created, this.content, this.userRoles);
    }

    /**
     * Returns a new Note with updated content.
     * The content is sanitized using AntiSamy to prevent attacks, a warning is logged if content required sanitization.
     *
     * @param content The new content for the note.
     * @return A new Note instance with the updated content.
     */
    public Note withContent(String content) {
            return new Note( this.id
                           , this.author
                           , this.name
                           , this.created
                           , content
                           , this.userRoles);
    }

    /**
     * Returns a new Note with the updated user roles.
     *
     * @param userRoles The new map of user roles.
     * @return A new Note instance with the updated user roles.
     */
    public Note withUserRoles(Map<UUID, Role> userRoles) {
        return new Note(this.id
                       , this.author
                       , this.name
                       , this.created
                       , this.content
                       , userRoles);
    }
    
    /**
     * Returns a new Note updating role for the specified user.
     *
     * @param user The user to whom the role is updated.
     * @param permission The role.
     * @return A new Note instance with the updated role for the user.
     */
    public Note withUserRole(User user, Role role) {
    
        return new Note( this.id
                       , this.author
                       , this.name
                       , this.created
                       , this.content
                       , userRoles.put(user.id, role));
    }

    /**
     * Saves the note to the database.
     * Updates the note if it exists, or inserts it as new if it does not exist.
     * The associated roles are also saved to the database.
     * Remember to call this transactionally, using @Transactional.
     *
     * @param jdbcTemplate The JdbcTemplate to interact with the database.
     */
    public void save(JdbcTemplate jdbcTemplate) {
        final String checkNoteExists = "SELECT COUNT(*) FROM Note WHERE id = ?";
        final Integer count = jdbcTemplate.queryForObject(checkNoteExists, Integer.class, id.toString());

        if (count != null && count > 0) {
            // Note exists, update it
            final String updateNote
                = "UPDATE Note SET author = ?, name = ?, content = ? WHERE id = ?";
            jdbcTemplate.update(updateNote, author.id, name, content, id.toString());
        } else {
            // Note does not exist, insert it
            final String insertNote = "INSERT INTO Note (id, author, name, created, content) VALUES (?, ?, ?, ?, ?)";
            jdbcTemplate.update(insertNote, id.toString(), author.id, name, created.toString(), content);
        }

        // Delete existing roles
        final String deleteRoles = "DELETE FROM NoteUserRoles WHERE note = ?";
        jdbcTemplate.update(deleteRoles, id.toString());

        // Insert new roles
        final String insertRole = "INSERT INTO NoteUserRoles (note, user, role) VALUES (?, ?, ?)";
        for (Tuple2<UUID, Role> entry : userRoles) {
            UUID userid = entry._1;
            Role role = entry._2;
            jdbcTemplate.update(insertRole, id.toString(), userid.toString(), role.toString());

        }
    }

    /**
     * Loads permissions for the specified note from the database.
     * @param jdbcTemplate The JdbcTemplate to interact with the database.
     * @param noteId The unique identifier of the note.
     * @return A map of user permissions for the note.
     */
    public static Map<UUID, Set<Permission>> loadPermissions(JdbcTemplate jdbcTemplate, UUID noteId) {
        final String sql = """
            SELECT nur.user, rp.permission
            FROM NoteUserRoles nur
            JOIN RolePermissions rp ON nur.role = rp.role
            WHERE nur.note = ?
        """; 

        logger.info("Loading permissions for note:" + noteId.toString());

        return jdbcTemplate.query(sql, (rs) -> {
            Map<UUID, Set<Permission>> permissionsMap = HashMap.empty();

            while (rs.next()) {
                UUID userId = UUID.fromString(rs.getString("user"));

                Permission permission = Permission.valueOf(rs.getString("permission").toUpperCase());

                permissionsMap = permissionsMap.put(userId, permissionsMap.get(userId)
                        .map(existingSet -> existingSet.add(permission))
                        .getOrElse(HashSet.of(permission)));
            }

            return permissionsMap;
        }, noteId.toString());
    }

    /**
     * Loads roles for the specified note from the database.
     * @param jdbcTemplate The JdbcTemplate to interact with the database.
     * @param noteId The unique identifier of the note.
     * @return A map of user roles for the note.
     */
    public static Map<UUID, Role> loadRoles(JdbcTemplate jdbcTemplate, UUID noteId) {
        final String sql = """
                SELECT user, role
                FROM NoteUserRoles
                WHERE note = ?
                """;

        logger.info("Loading roles for note:" + noteId.toString());

        return jdbcTemplate.query(sql, (rs) -> {
            Map<UUID, Role> rolesMap = HashMap.empty();
    
            while (rs.next()) {
                UUID userId = UUID.fromString(rs.getString("user"));
                Role role = Role.valueOf(rs.getString("role").toUpperCase());
    
                // Insert the role directly for each user
                rolesMap = rolesMap.put(userId, role);
            }
    
            return rolesMap;
        }, noteId);
    }

    /**
     * Loads a note from the database along with its permissions.
     *
     * @param jdbcTemplate The JdbcTemplate to interact with the database.
     * @param noteId The unique identifier of the note.
     * @return The Note object loaded from the database.
     * @throws IllegalArgumentException If the note is not found in the database.
     */
    public static Note load(JdbcTemplate jdbcTemplate, UUID noteId) {
        final String sql =  """
                              SELECT n.id, n.author, n.name, n.created, n.content, a.username as author_name, a.password AS author_password
                              FROM Note n
                              JOIN USER a ON a.id = n.author
                              WHERE n.id = ?
                            """;

        Map<UUID, Role> roles = loadRoles(jdbcTemplate, noteId);
        logger.info("Loading note:" + noteId.toString());
        Note note = jdbcTemplate.queryForObject(sql, (rs, rowNum) -> new Note(
                UUID.fromString(rs.getString("id")),
                new User(UUID.fromString(rs.getString("author")), rs.getString("author_name"), rs.getString("author_password")),
                rs.getString("name"),
                Instant.parse(rs.getString("created")),
                rs.getString("content"),
                roles
        ), noteId.toString());

        if (note == null) {
            throw new IllegalArgumentException("Note not found.");
        }

        return note;
    }

    // Sanitize content using AntiSamy-slashdot policy
    private String sanitizedContent(String content) {
        try (InputStream policyStream = getClass().getClassLoader().getResourceAsStream("antisamy-slashdot.xml")) {
            if (policyStream == null) {
                throw new IllegalArgumentException("Policy file not found.");
            }
            Policy policy = Policy.getInstance(policyStream);
            AntiSamy antiSamy = new AntiSamy();
            CleanResults cleanResults = antiSamy.scan(content, policy);
            String sanitizedContent = cleanResults.getCleanHTML();

            //log encountered errors
            if (cleanResults.getNumberOfErrors() > 0) {
                cleanResults.getErrorMessages().stream()
                    .filter(e -> !e.contains("The p tag was empty"))
                    .forEach(e -> logger.warn(
                        "note: {}, message: illegal content sanitized, potential attempted attack, error: {}", 
                        this.id, 
                        e
                    ));
            }

            return sanitizedContent;

        } catch (PolicyException | ScanException | IOException e) {
            logger.error("Error while sanitizing content: " + e.getMessage());
            throw new RuntimeException("Failed to sanitize content", e);
        }
    }
}