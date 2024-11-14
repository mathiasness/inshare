package no.bufferoverflow.inshare;

import java.time.LocalDateTime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.stereotype.Component;

/**
 * Class for logging authentication events.
 */
@Component
public class AuthenticationLogger {
    /*Logger for Authentication */
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationLogger.class);

    /**
     * Logs a successful login event.
     * Logs an info message with the username and timestamp of the successful login.
     * @param event the successful login event
     */
    @EventListener
    public void loginEvent(AuthenticationSuccessEvent event) {
        User user = ((User) event.getAuthentication().getPrincipal());
        LocalDateTime timestamp = LocalDateTime.now();

        logger.info("user: {}, timestamp: {}, message: logged in successfully", user.id, timestamp);
    }

    /**
     * Logs a successful logout event.
     * Logs an info message with the username and timestamp of the successful logout.
     * @param event the successful logout event
     */
    @EventListener
    public void logoutEvent(LogoutSuccessEvent event) {
        User user = ((User) event.getAuthentication().getPrincipal());
        LocalDateTime timestamp = LocalDateTime.now();

        logger.info("user: {}, timestamp: {}, message: logged out", user.id, timestamp);
    }

    /**
     * Logs a failed login event.
     * Logs a warning message with the username and timestamp of the failed login attempt.
     * @param event the failed login event
     */
    @EventListener
    public void failedLoginEvent(AuthenticationFailureBadCredentialsEvent event) {
        String username = (String) event.getAuthentication().getPrincipal();
        LocalDateTime timestamp = LocalDateTime.now();

        logger.warn("attempted username: {}, timeStamp: {}, message: Failed login attempt", username, timestamp);
    }
}
