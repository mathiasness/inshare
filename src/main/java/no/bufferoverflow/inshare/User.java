package no.bufferoverflow.inshare;


import java.util.Collection;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import io.ebean.uuidv7.UUIDv7;
import io.vavr.collection.List;
import io.vavr.collection.Set;

import java.time.Instant;

public final class User implements UserDetails, Comparable<User> {

    /** Unique identifier for the user, generated using UUIDv7. */
    public final UUID id;
    /** Username used for authentication. Must be unique in the system. */
    public final String username;
    /** Password for the user. */
    public final String password;

    /**
     * Constructs a user object with the specified unique
     * identifier, username, and password.
     *
     * @param id       the unique identifier for the user.
     * @param username the username used for authentication.
     * @param password the password for the user, stored in a hashed format.
     */
    public User(UUID id, String username, String password) {
        this.id = id;
        this.username = username;
        this.password = password;
    }
    /**
     * Constructs a new user with a randomly generated
     * unique identifier, given a username and password.
     *
     * @param username the username used for authentication.
     * @param password the password for the user, stored in a hashed format.
     */
    public User(String username, String password) {
        this(UUIDv7.generate(), username, password);
    }
    /**
     * Returns a new {@code User} object with an updated username.
     *
     * @param username the new username for the user.
     * @return a new {@code User} instance with the updated username.
     */
    public User withUsername(String username) {
        return new User(this.id, username,this.password);
    }
    /**
     * Returns a new {@code User} instance with the same ID and username,
     * but with an updated password.
     *
     * @param password the new password for the user.
     * @return a new {@code User} instance with the updated password.
     */
    public User withPassword(String password) {
        return new User(this.id,this.username,this.password);
    }

    /**
     * Saves this user to the database using the provided {@link JdbcTemplate}.
     * If a user with the same ID already exists, this will update the existing entry.
     * 
     * Remember to call this function transactionally (i.e. using @Transactional)
     *
     * @param jdbcTemplate the {@link JdbcTemplate} used to interact with the database.
     */
    public void save(JdbcTemplate jdbcTemplate) {
        final String insert = "INSERT INTO User (id, username, password) VALUES (?, ?, ?)";

        jdbcTemplate.update(insert, id.toString(), username, password);
    }

    /**
     * Loads a user from the database with the specified username.
     *
     * @param jdbcTemplate the {@link JdbcTemplate} used to interact with the database.
     * @param username     the username of the user to load.
     * @return the {@code User} object corresponding to the given username.
     * @throws UsernameNotFoundException if no user with the specified username is found.
     */
    public static User load(JdbcTemplate jdbcTemplate, String username) {
        final String sql = "SELECT id, username, password FROM User WHERE username = ?";
        final User user = jdbcTemplate.queryForObject(sql, (rs, rowNum) -> 
                new User(UUID.fromString(rs.getString("id")), rs.getString("username"), rs.getString("password")), username );
        if (user == null)
            throw new UsernameNotFoundException("No such username.");
        return user;
    }

    /**
     * Loads all notes that this user has read permissions for.
     *
     * @param jdbcTemplate the {@link JdbcTemplate} used to interact with the database.
     * @return a {@link Set} of {@link Note} objects that this user can read.
     */
    public Set<Note> loadReadableNotes(JdbcTemplate jdbcTemplate) {
        final String sql = """
            SELECT n.id, n.name, n.created, n.content, u.username, a.id AS author_id, a.username AS author_username, a.password AS author_password
            FROM Note n
            JOIN NoteUserRoles nur ON n.id = nur.note
            JOIN RolePermissions rp ON nur.role = rp.role
            JOIN User u ON nur.user = u.id
            JOIN User a ON n.author = a.id
            WHERE u.username = ? AND rp.permission = 'READ'
            """;

        return io.vavr.collection.HashSet.ofAll(jdbcTemplate.query(sql, (rs, rowNum) -> 
            new Note(
                UUID.fromString(rs.getString("id")),
                new User(
                    UUID.fromString(rs.getString("author_id")),
                    rs.getString("author_username"),
                    rs.getString("author_password")
                ),
                rs.getString("name"),
                Instant.parse(rs.getString("created")),
                rs.getString("content"),
                Note.loadRoles(jdbcTemplate, UUID.fromString(rs.getString("id")))
            ), username
        ));
    }

    
    @Override
    public String getPassword() {
        return "{argon2}" + password;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
         List<GrantedAuthority> ret = List.of();
         return ret.toJavaList();
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean equals(Object other){
        if (other instanceof User)
            return this.id.equals(((User) other).id);
        return false;
    }

    @Override
    public int compareTo(User other) {
        return this.id.compareTo(other.id);
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }
}
