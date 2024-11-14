package no.bufferoverflow.inshare;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import io.vavr.collection.HashMap;
import io.vavr.collection.HashSet;
import io.vavr.collection.Map;
import io.vavr.collection.Set;
import no.bufferoverflow.inshare.Note.Permission;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.UUID;

/**
 * Controller for handling note operations, such as viewing, editing,
 * creating, deleting, and sharing notes. It integrates with the database using
 * {@link JdbcTemplate} and manages user-specific permissions.
 */
@Controller
@RequestMapping("/note")
public class NoteController {


    /** Template for executing SQL queries against the database. */
    private final JdbcTemplate jdbcTemplate;
    /** Service for loading user details and authentication. */
    private final InShareUserDetailService userDetailService;

    /** Logger for the NoteController class. */
    private static final Logger logger = LoggerFactory.getLogger(NoteController.class);

    public NoteController(JdbcTemplate jdbcTemplate, InShareUserDetailService userDetailService) {
        this.jdbcTemplate = jdbcTemplate;
        this.userDetailService = userDetailService;
    }

    /**
     * Show the view page for a note
     *
     * @param id the unique identifier of the note.
     * @param model the UI model which will be passed to the template. Modified by this method.
     * @return the name of the template ("viewNote")
     */
    @GetMapping("/view/{id}")
    public String showViewForm(@PathVariable("id") UUID id, Model model) {
        Note note = Note.load(jdbcTemplate, id);
        model.addAttribute("note", note);

        if (checkPermission(id, Permission.READ)) {
            logNoteAction(id, "viewed note", false);
            return "viewNote"; // Check if user has read permission before displaying note
        } else {
            logNoteAction(id, "Tried to view without READ permission", true);
            return "redirect:/"; // Redirect to dashboard if user does not have read permission
        }
    }
    
    /**
     * Displays the form to edit an existing note.
     *
     * @param id the unique identifier of the note.
     * @param model the UI model which will be passed to the template. Modified by this method.
     * @return the view name for editing the note, "editNote"
     */
    @GetMapping("/edit/{id}")
    public String showEditForm(@PathVariable("id") UUID id, Model model) {
        Note note = Note.load(jdbcTemplate, id);
        model.addAttribute("note", note);
        if (checkPermission(id, Permission.WRITE)) { // Check if user has write permission before displaying edit form
            logNoteAction(id, "User entered edit form", false);
            return "editNote";
        } else { // Redirect to dashboard if user does not have write permission
            logNoteAction(id, "Tried to enter edit form without WRITE permission", true);
            return "redirect:/"; 
        }
    }

    /**
     * Handles the submission of the edit form and updates the note in the database.
     * This operation is transactional to ensure the note is updated atomically.
     *
     * @param id the unique identifier of the note to be updated.
     * @param name the new name for the note.
     * @param content the new content for the note.
     * @return a redirect to the dashboard after the update.
     */
    @PostMapping("/edit/{id}")
    @Transactional
    public String updateNote(@PathVariable("id") UUID id,
                             @RequestParam("name") String name,
                             @RequestParam("content") String content) {
        Note note = Note.load(jdbcTemplate, id)
                        .withName(name)
                        .withContent(content);

        if (checkPermission(id, Permission.WRITE)){
            note.save(jdbcTemplate); // Check if user has write permission before saving changes
            logNoteAction(id, "User updated note", false);
        } else {
            logNoteAction(id, "Tried to update note content without WRITE permission", true);
        }
        return "redirect:/"; // Redirect to dashboard after update
    }


    /**
     * Handles the creation of a new note and assigns default permissions to the
     * authenticated user. This operation is transactional to ensure the note
     * creation and permission assignment are atomic.
     *
     * @param name the name of the new note.
     * @param content the content of the new note.
     * @return a redirect to the edit view of the newly created note.
     */
    @PostMapping("/create")
    @Transactional
    public String createNote(@RequestParam("name") String name,
                             @RequestParam("content") String content) {



        final Authentication authentication
            = SecurityContextHolder.getContext()
                                   .getAuthentication();

        if (authentication != null && authentication.isAuthenticated()
                && (authentication.getPrincipal() instanceof User)) {
            final User user = (User)authentication.getPrincipal();
            final Note newNote = new Note(user, name, content)
                                .withUserRole(user, Note.Role.OWNER);
                                
            newNote.save(jdbcTemplate);
            logNoteAction(null, "created new note", false);
            return "redirect:/note/edit/" + newNote.id.toString();
        }
        return "redirect:/";
    }

    
    /**
     * Deletes the specified note if the authenticated user has the DELETE permission.
     * This operation is transactional to ensure the note
     * deletion is performed atomically.
     *
     * @param id the unique identifier of the note to be deleted.
     * @return a redirect to the dashboard after deletion.
     */
    @DeleteMapping("/delete/{id}")
    @Transactional
    public ResponseEntity<?> deleteNote(@PathVariable("id") UUID id) {
        if (checkPermission(id, Permission.DELETE)) {
            final String deleteNote = "DELETE FROM Note WHERE id = ?";
            jdbcTemplate.update(deleteNote, id.toString());
            logNoteAction(id, "User deleted note", false);
            return ResponseEntity.ok().body("{\"message\": \"Note deleted successfully!\"}");
        } else {
            // Return forbidden status if user lacks permissions
            logNoteAction(id, "Tried to delete note without DELETE permission", true);
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                .body("{\"error\": \"You do not have permission to delete this note.\"}");
        }   
    }

    /**
     * Displays the form to share a note with another user.
     *
     * @param id the unique identifier of the note.
     * @param model the model to which the note is added.
     * @return the view name for sharing the note.
     */
    @GetMapping("/share/{id}")
    public String showShareForm(@PathVariable("id") UUID id, Model model) {
        Note note = Note.load(jdbcTemplate, id);
        boolean isOwner = checkRole(id, Note.Role.OWNER);

        model.addAttribute("note", note);
        model.addAttribute("isOwner", isOwner);
        
        if (checkRole(id, Note.Role.OWNER) || checkRole(id, Note.Role.ADMINISTRATOR)) {
            logNoteAction(id, "Entered share form", false);
            return "shareNote";
        } else {
            logNoteAction(id, "Tried to enter share form without OWNER or ADMINISTRATOR role", true);
            return "redirect:/"; // Redirect to dashboard if user does not have permission to share
        }
    }

    /**
     * Retrieves the permissions associated with the specified note for the
     * authenticated user.
     *
     * @param id the unique identifier of the note.
     * @return a map containing the permissions of the authenticated user for the note.
     */
    @GetMapping("/permissions/{id}") 
    @ResponseBody
    public Map<String, Object> getNotePermissions(@PathVariable("id") UUID id) {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = (User) authentication.getPrincipal();

        Set<Note.Permission> permissions = Note.loadPermissions(jdbcTemplate, id)
                .get(user.id)
                .getOrElse(HashSet.of());
        return HashMap.of("permissions", permissions.toJavaSet());
    }


    /**
     * Shares the specified note with another user and grants them the specified permissions.
     * This operation is transactional to ensure the permissions are added atomically.
     *
     * @param noteId the unique identifier of the note to be shared.
     * @param username the username of the user with whom the note is shared.
     * @param permissions the list of permissions to be granted.
     * @return a redirect to the dashboard after sharing.
     * @throws UsernameNotFoundException if the specified user is not found.
     */
    @PostMapping("/share")
    @Transactional
    public String shareNote(
            @RequestParam UUID noteId,
            @RequestParam String username,
            @RequestParam Note.Role role) {

        // Load the note
        Note note = Note.load(jdbcTemplate, noteId);
        
        // Load the user
        User user;
        try {
            user = (User) userDetailService.loadUserByUsername(username);
            if (user == null) {
                throw new UsernameNotFoundException("User not found: " + username);
            }
        } catch (UsernameNotFoundException e) {
            logNoteAction(noteId, "Tried to share note with non-existent user", true);
            return "redirect:/";
        }

        //the issuer
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User issuer = (User) authentication.getPrincipal();
        if (user.id.equals(issuer.id)) { //cannot share with self
            logNoteAction(noteId, "Tried to share with self", true);
            return "redirect:/";
        }

        // check role of the issuer, only owner or administrator can share
        Note.Role issuerRole = note.userRoles.get(issuer.id).getOrElse(Note.Role.READER);
        if (!issuerRole.equals(Note.Role.OWNER) && !issuerRole.equals(Note.Role.ADMINISTRATOR)) {
            logNoteAction(noteId, "Tried to share without OWNER or ADMINISTRATOR role", true);
            return "redirect:/"; 
        }

        if (role.equals(Note.Role.OWNER)) { // only owner can transfer ownership
            if (issuerRole.equals(Note.Role.OWNER)) {
                logNoteAction(noteId, "Transfered ownership", false);
                note = note.withUserRole(issuer, Note.Role.ADMINISTRATOR); //remove ownership
            } else {
                logNoteAction(noteId, "Tried to transfer ownership without OWNER role", true);
                return "redirect:/";
            }
        }
        
        note = note.withUserRole(user, role);
        logNoteAction(noteId, "Shared note", false);
        note.save(jdbcTemplate);
        return "redirect:/";
    }

    /**Checks if the authenticated user has the given role*/
    private boolean checkRole(UUID noteId, Note.Role role) {
        final Authentication authentication
            = SecurityContextHolder.getContext()
                                   .getAuthentication();

        if (authentication != null && authentication.isAuthenticated()
                && (authentication.getPrincipal() instanceof User)) {
            final User user = (User)authentication.getPrincipal();
            Note note = Note.load(jdbcTemplate, noteId);
            return note.userRoles.get(user.id).getOrElse(Note.Role.READER).equals(role);
        } else return false;
    }

    /**Checks if the authenticated user has the given permission*/
    private boolean checkPermission(UUID noteId, Permission permission) {
        final Authentication authentication
            = SecurityContextHolder.getContext()
                                   .getAuthentication();

        if ( authentication != null
                && authentication.isAuthenticated()
                && (authentication.getPrincipal() instanceof User)) {
            final User user = (User)authentication.getPrincipal();
            Map<UUID, Set<Permission>> permissions = Note.loadPermissions(jdbcTemplate, noteId);
            return permissions.get(user.id).getOrElse(HashSet.of()).contains(permission);
        } else return false;
    }

    /**Utility helper method to log note actions*/
    private void logNoteAction(UUID noteId, String message, boolean error) {
        final Authentication authentication
            = SecurityContextHolder.getContext()
                                   .getAuthentication();

        if (authentication != null && authentication.isAuthenticated()
                && (authentication.getPrincipal() instanceof User)) {
            final User user = (User)authentication.getPrincipal();

            if (error) logger.error("User: {}, note: {}, message: {}", user.id, noteId, message);
            else logger.info("User: {}, note: {}, message: {}", user.id, noteId, message);
        }
    }
}
