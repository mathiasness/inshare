package no.bufferoverflow.inshare;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

public class RegistrationControllerTest {

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Mock
    private PasswordEncoder encoder;

    @InjectMocks
    private RegistrationController registrationController;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testSuccessfulRegistrationWithValidUsernameAndPassword() {
        // Mock data
        String username = "validUser";
        String password = "StrongPass1!";
        String hashedPassword = "hashedPassword123";

        // Mocking behavior
        when(jdbcTemplate.queryForObject(anyString(), eq(Integer.class), eq(username))).thenReturn(0); // Username doesn't exist
        when(encoder.encode(password)).thenReturn(hashedPassword); // Mock password hashing

        // Setting up the registration DTO
        RegistrationController registrationController = new RegistrationController(jdbcTemplate, encoder);
        RegistrationController.UserRegistrationDto registrationDto = registrationController.new UserRegistrationDto();
        registrationDto.setUsername(username);
        registrationDto.setPassword(password);

        // Call the register method
        ResponseEntity<RegistrationController.RegistrationResponse> response = registrationController.register(registrationDto);

        // Assertions
        assertNotNull(response);
        assertTrue(response.getBody().success);
        assertEquals("Registration successful!", response.getBody().message);
        verify(encoder).encode(password); // Check that password hashing was performed
    }

    @Test
    public void testRegistrationFailsForInvalidUsername() {
        // Mock data
        String invalidUsername = "inv"; // Username less than 6 characters
        String password = "ValidPass1!";

        // Setting up the registration DTO
        RegistrationController registrationController = new RegistrationController(jdbcTemplate, encoder);
        RegistrationController.UserRegistrationDto registrationDto = registrationController.new UserRegistrationDto();
        registrationDto.setUsername(invalidUsername);
        registrationDto.setPassword(password);

        // Call the register method
        ResponseEntity<RegistrationController.RegistrationResponse> response = registrationController.register(registrationDto);

        // Assertions
        assertNotNull(response);
        assertFalse(response.getBody().success);
        assertEquals("Username must be between 6 and 20 characters long and contain only letters, numbers and underscores!", response.getBody().message);
        verify(encoder, never()).encode(anyString()); // Password hashing should not be called
    }

    @Test
    public void testRegistrationFailsForWeakPassword() {
        // Mock data
        String username = "validUsername";
        String weakPassword = "weak"; // Weak password (less than 8 characters, no uppercase or special characters)

        // Setting up the registration DTO
        RegistrationController registrationController = new RegistrationController(jdbcTemplate, encoder);
        RegistrationController.UserRegistrationDto registrationDto = registrationController.new UserRegistrationDto();
        registrationDto.setUsername(username);
        registrationDto.setPassword(weakPassword);

        // Call the register method
        ResponseEntity<RegistrationController.RegistrationResponse> response = registrationController.register(registrationDto);

        // Assertions
        assertNotNull(response);
        assertFalse(response.getBody().success);
        assertEquals("Password must be at least 8 characters long and contain at least one uppercase letter, one number and one special character!", response.getBody().message);
        verify(encoder, never()).encode(anyString()); // Password hashing should not be called
    }

    @Test
    public void testRegistrationFailsForExistingUsername() {
        // Mock data
        String existingUsername = "existingUser";
        String password = "ValidPass1!";

        // Mock behavior for existing username
        when(jdbcTemplate.queryForObject(anyString(), eq(Integer.class), eq(existingUsername))).thenReturn(1); // Username already exists

        // Setting up the registration DTO
        RegistrationController registrationController = new RegistrationController(jdbcTemplate, encoder);
        RegistrationController.UserRegistrationDto registrationDto = registrationController.new UserRegistrationDto();
        registrationDto.setUsername(existingUsername);
        registrationDto.setPassword(password);

        // Call the register method
        ResponseEntity<RegistrationController.RegistrationResponse> response = registrationController.register(registrationDto);

        // Assertions
        assertNotNull(response);
        assertFalse(response.getBody().success);
        assertEquals("Username already taken!", response.getBody().message);
        verify(encoder, never()).encode(anyString()); // Password hashing should not be called
    }

    @Test
    public void testCheckUsernameFormat() {
        // Valid usernames
        assertTrue(PasswordUtils.checkUsernameFormat("validUser"));
        assertTrue(PasswordUtils.checkUsernameFormat("user1234"));
        assertTrue(PasswordUtils.checkUsernameFormat("user_name"));

        // Invalid usernames
        assertFalse(PasswordUtils.checkUsernameFormat("us")); // Too short
        assertFalse(PasswordUtils.checkUsernameFormat("user*name")); // Contains invalid character *
        assertFalse(PasswordUtils.checkUsernameFormat("thisusernameistoolongforvalidation")); // Exceeds max length
    }

    @Test
    public void testCheckPasswordFormat() {
        // Valid passwords
        assertTrue(PasswordUtils.checkPasswordFormat("ValidPass1!")); // Meets all criteria
        assertTrue(PasswordUtils.checkPasswordFormat("ValidPass1!")); // Meets all criteria
        assertTrue(PasswordUtils.checkPasswordFormat("Strong1@")); // Minimum length, includes uppercase, number, and special character
        // Invalid passwords
        assertFalse(PasswordUtils.checkPasswordFormat("weakpass")); // No uppercase, number, or special character
        assertFalse(PasswordUtils.checkPasswordFormat("Weakpass")); // No number or special character
        assertFalse(PasswordUtils.checkPasswordFormat("weakpass1!")); // No uppercase letter
        assertFalse(PasswordUtils.checkPasswordFormat("SHORT1!")); // Less than 8 characters
    }

}
