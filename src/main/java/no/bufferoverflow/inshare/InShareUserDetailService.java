package no.bufferoverflow.inshare;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class InShareUserDetailService implements UserDetailsService {

    private final JdbcTemplate jdbcTemplate;

    public InShareUserDetailService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            return User.load(jdbcTemplate, username);
        } catch (EmptyResultDataAccessException e) {
            throw new UsernameNotFoundException("User not found: " + username, e);
        }
    }
}
