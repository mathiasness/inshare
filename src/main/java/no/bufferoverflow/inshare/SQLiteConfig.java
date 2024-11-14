package no.bufferoverflow.inshare;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

@Configuration
public class SQLiteConfig {

    private static final Logger logger = LoggerFactory.getLogger(SQLiteConfig.class);

    @Bean
    public CommandLineRunner enableForeignKeys(JdbcTemplate jdbcTemplate) {
        return args -> {
            logger.info("Enabling foreign key support for SQLite database.");
            jdbcTemplate.execute("PRAGMA foreign_keys = ON;");
            jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS User (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL
                );
                """);
            jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS Note (
                    id TEXT PRIMARY KEY,
                    author TEXT,
                    name TEXT NOT NULL,
                    created TEXT NOT NULL,
                    content TEXT NOT NULL,
                    FOREIGN KEY (author) REFERENCES User(id) on DELETE CASCADE
                );
                """);
            jdbcTemplate.execute("""
                    CREATE TABLE IF NOT EXISTS Permission (
                        name TEXT PRIMARY KEY
                    );
                """);
            jdbcTemplate.execute("""
                    INSERT INTO Permission (name) 
                    VALUES 
                        ('READ'),
                        ('WRITE'),
                        ('DELETE')
                    ON CONFLICT(name) DO NOTHING;
                """);

                //create new table for roles
            jdbcTemplate.execute("""
                    CREATE TABLE IF NOT EXISTS Roles (
                        name TEXT PRIMARY KEY
                    );
                """);
                
                //insert roles into table
            jdbcTemplate.execute("""
                    INSERT INTO Roles (name) 
                    VALUES 
                        ('OWNER'),
                        ('ADMINISTRATOR'),
                        ('EDITOR'),
                        ('READER')
                    ON CONFLICT(name) DO NOTHING;
                """);
            
                //create new table for rolePermissions
            jdbcTemplate.execute("""
                    CREATE TABLE IF NOT EXISTS RolePermissions (
                        role TEXT NOT NULL,
                        permission TEXT NOT NULL,
                        PRIMARY KEY (role,permission),
                        FOREIGN KEY (role) REFERENCES Roles(name) ON DELETE CASCADE,
                        FOREIGN KEY (permission) REFERENCES Permission(name) ON DELETE CASCADE
                    );
                """);

                //insert roles with permissions
            jdbcTemplate.execute("""
                    INSERT INTO RolePermissions (role, permission) 
                    VALUES 
                        ('OWNER', 'READ'),
                        ('OWNER', 'WRITE'),
                        ('OWNER', 'DELETE'),
                        ('ADMINISTRATOR', 'READ'),
                        ('ADMINISTRATOR', 'WRITE'),
                        ('ADMINISTRATOR', 'DELETE'),
                        ('EDITOR', 'READ'),
                        ('EDITOR', 'WRITE'),
                        ('READER', 'READ')
                    ON CONFLICT(role,permission) DO NOTHING;
                """);
                
                //create new table for userRoles
            jdbcTemplate.execute("""
                    CREATE TABLE IF NOT EXISTS NoteUserRoles (
                        user TEXT NOT NULL,
                        note TEXT NOT NULL,
                        role TEXT NOT NULL,
                        PRIMARY KEY (user,note,role),
                        FOREIGN KEY (user) REFERENCES User(id) ON DELETE CASCADE,
                        FOREIGN KEY (note) REFERENCES Note(id) ON DELETE CASCADE,
                        FOREIGN KEY (role) REFERENCES Roles(name) ON DELETE CASCADE
                    );
                """);

            logger.info("DB initizialized.");
        };
    }
}
