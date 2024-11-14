package no.bufferoverflow.inshare;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import io.vavr.collection.HashSet;
import io.vavr.collection.Set;


@Controller
public class HomeController {
    /** Template for executing SQL queries against the database. */
    private final JdbcTemplate jdbcTemplate;

    public HomeController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Displays the home page. If the user is authenticated, it loads the user's readable notes
     * and displays the private dashboard. Otherwise, it redirects to the public front page.
     *
     * @param model the UI model to which user-specific and note data are added.
     * @return the view name of the dashboard for authenticated users, or a redirect to the public page.
     */
    @GetMapping("/")
    public String home(Model model) {
        
        final Authentication authentication
            = SecurityContextHolder.getContext()
                                   .getAuthentication();
        
        if (authentication != null && authentication.isAuthenticated()
                && (authentication.getPrincipal() instanceof User)) {
                final User user = (User)authentication.getPrincipal();
                model.addAttribute("username", user.getUsername());
                model.addAttribute("userid",user.id);
                // Return private homepage template if user is authenticated

                // Load notes that the user has read access to
                Set<Note> readableNotes = user.loadReadableNotes(jdbcTemplate);
                model.addAttribute("notes"
                                  ,readableNotes
                                      .toSortedSet(Note.byCreationDate.reversed()));
                model.addAttribute("emptyset", HashSet.of());
                model.addAttribute("read", Note.Permission.READ);
                model.addAttribute("write", Note.Permission.WRITE);
                model.addAttribute("delete", Note.Permission.DELETE);
                
                // role attributes
                model.addAttribute("owner", Note.Role.OWNER);
                model.addAttribute("editor", Note.Role.EDITOR);
                model.addAttribute("admin", Note.Role.ADMINISTRATOR);
                model.addAttribute("reader", Note.Role.READER);

                return "dashboard";
        }

        // Redirect to public page if not authenticated
        return "redirect:/public";
    }
    
    /**
     * Displays the public front page for unauthenticated users.
     *
     * @return the view name for the public front page.
     */
    @GetMapping("/public")
    public String publicFront() {
        return "public";
    }
    
}
