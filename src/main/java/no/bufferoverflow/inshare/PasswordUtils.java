package no.bufferoverflow.inshare;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


/**
 * Class for password utilities
 */
@Configuration
public class PasswordUtils {

    /**
     * Bean for password encoder
     * @return PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Argon2PasswordEncoder(16, 32, 1, 1 << 13, 2);
    }

    /**
     * Check if the username is in the correct format
     * @param username
     * @return boolean
     */
    public static boolean checkUsernameFormat(String username) {
        return username.matches("^[a-zA-Z0-9_]{6,20}$");
    }   

    /**
     * Check if the password is in the correct format
     * @param password
     * @return boolean
     */
    public static boolean checkPasswordFormat(String password) {
        return password.length() >= 8
        && password.matches(".*[0-9].*")
        && password.matches(".*[A-Z].*")
        && password.matches(".*[^a-zA-Z0-9].*");
    }
}
