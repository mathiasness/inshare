# Mandatory Assignment 3 – INF226 – 2024

Welcome to the third and final mandatory assignment of INF226 (Software Security). In this assignment, you will be improving the security of a program called InShare—a note-sharing web application that has been deliberately crafted to include a number of security flaws. As you discovered in the previous assignment, InShare suffers from vulnerabilities that compromise its security.

Your task is to analyze these vulnerabilities, plan improvements, and ultimately secure the application. You will be working in phases, focusing on design, implementation and review.

From the learning outcomes of the course:

 - "The student masters, theoretically and practically, programming techniques to develop
secure, safe, reliable, and robust systems, and can assess the security of given source code or application."
 - "The student can plan and carry out varied assignments and projects for secure software, can develop critical thinking about secure software, can exchange opinions with other professionals and participate in developing best practices for secure software."


## Group Work

This project is to be carried out by groups of 1–3 students. You may choose to retain your previous group from earlier assignments, or you can form a new group. Make sure that everyone is signed up for the group on MittUiB. **Note:** This assignment includes a bit more programming than the previous assignments, so even if you worked alone on the previous assignments, you may consider forming a group for this one. Even if you prefer to work alone, you are strongly
 encouraged to find another which can review your code.

We encourage collaboration through GitLab for branching, merge requests, and peer review. Each member of the group is expected to contribute to both the analysis and implementation of the security improvements.

# Phases and Iteration

The assignment is divided into three phases: Planning, Implementation and Review. These phases are not disjoint, and you should expect a feedback loop where planning, implementation, testing and review may cycle multiple times.

You will be working on each phase simultaneously, addressing different areas of security (e.g., authentication, SQL injection, access control, CSRF, XSS) at various stages of completion. This mirrors real-world software development processes, where issues are identified, planned for, fixed, and reviewed iteratively.

## Forking the Project on GitLab

To get started, you will first need to fork the InShare project on GitLab. Visit the project repository on the [UiB GitLab instance](https://git.app.uib.no) and click on the "Fork" button to create your own copy of the project. Once your fork is created, make sure to set the repository to private under the project settings.

You must also give access to the TAs and the lecturer. To do this, go to the "Manage" → "Members" section of your repository and add the teachers as developers:

 - Håkon Gylterud
 - Willem Schooltink
 - Shania Muganga
 - Jonas Haukenes
 - Julie Mikkelsen
 - Endre Sletnes
 - Eivind Sulen

GitLab will be your main platform for collaboration, where you can create branches for working on different parts of the code, open issues to document vulnerabilities, and create merge requests for peer review. Ensure that all members of your group actively contribute by using branches and reviewing each other’s work.

**Remember to add any libraries you want to use to the pom.xml file.**

## Documenting your work

**Fill out the report in the bottom of this page as you go along.** It is divided into sections already with some suggestions what to write.

## Phase 1: Planning mitigations

In the first phase you should plan how to improve the security of InShare. **Write down your planning in the report in the bottom of this page.**


### SQL injection

Plan the mitigation of SQL injection, and create GitLab issues for the fixes. How will you determine/test that the vulnerability is fixed?


### XSS

Plan the mitigation of existing XSS vulnerabilities. The cruicial part to consider is the content of notes.
The solution for text formatting *requires* use of HTML tags in the content of notes.
One possible solution would be to use an HTML Sanitiser (such as [OWASP AntiSamy](https://owasp.org/www-project-antisamy/)).

How will you determine that the vulnerability is fixed?

Create a mitigation plan and GitLab issues for the fixes.

### CSRF

Plan the mitigation of CSRF vulnerabilities in InShare, and create GitLab issues for the fixes.

How will you determine that the vulnerability is fixed?

### Authentication

In the previous assignment we identified weaknesses in the authentication system of InShare.
In particular there is no key derivation function applied to the password before storing it in the database,
and there are no requirements on password lengths.

Focussing on **password storage** using a key derivation function (Argon2 or scrypt are recommended)
and **ensuring user password strength**, create a plan
for improving the authentication system in InShare. Break the plan into GitLab issues.

Some things to consider:

 - Will there be any changes to the UI?
 - What are best practises to encourage users to pick a strong password?
 - How will you determine that the security of the authentication mechanism is improved?

### Access control

The problems with access control in InShare is twopart:

 - Insufficient checks on permissions: Most permissions are only enforced in the UI. Only the
   DELETE permission is checked in the backend.
 - Limited access control model: The access control list method is probably not the best
   fit for the application.

It will be practical to address the second issue first by replacing the access control system,
and then the second one by ensuring that the new access control system verifies all permissions
in the backend.

Plan for the creation of a Role Based Access Control (RBAC) for InShare:

 - Include a new database schema for the roles and permissions. Remember to set up foreign keys, and add additional constraints where suitable.
 - The roles should be:
   - "owner": Each note has a unique owner. Has read/write/delete permissions. Cannot be revoked, only transferred by the owner themselves.
   - "administrator": Has read/write/delete permissions. Can set roles (except owner).
   - "editor": Has read/write permissions.
   - "reader": Can only read the note.
 - Plan which methods on the backend have to include checks for permssions, and how this will be coordinated with the UI.
 - Change the UI so that the sharing mechanism uses the new roles. Include an option to transfer ownership of a note.
 - How will you determine that the security of the access control mechanism has improved?

### Logging

There is currently very little logging going on in InShare. Identify what logging is taking place, and plan the introduction
of more security logging. Make sure that you follow best practises on what to log and what not to log.

Create GitLab issues for adding logging to various parts of the code.

## Phase 2: Implementation

In this phase you will do the actual implementation of the fixes. Make the fixes on separate branches, and follow
the issues you have created. In the report you can mention any particular challenges you had to overcome in the
implementation.

### Impelment protections against SQL injection, XSS, CSRF

Working in separate branches, implement the fixes for SQL injection, XSS and CSRF, according to your plan from the
previous phase. Do not merge into the main branch until another team member has peer-reviewed your code. See next phase.

### Implement improvements to authentication

Working in a seprarate branch, implement the authentication changes planned in phase 1.
Do not merge into the main branch until another team member has peer-reviewed your code. See next phase.

### Implement improvements to access control

Working in a seprarate branch, implement the access control changes planned in phase 1.
Do not merge into the main branch until another team member has peer-reviewed your code. See next phase.

### Implement logging improvements

Working in a seprarate branch, follow the previous laid out plan to implement security logging.
Do not merge into the main branch until another team member has peer-reviewed your code. See next phase.


## Phase 3: Review and testing

**Note**: Even if you are working alone, get someone else from the course to review your code if at all possible.

In this phase you submit a merge request for each of the branches from the previous phase, and peer-review the changes.

 - Remember to test your code before submitting a merge request.
 - Be clear in the merge request what is being implemented, and which issues are affected.

When reviewing think about the following:

 - Focus on security.
 - Check that the code is readable and is clear.
 - Test the code. Checkout the branch and do some manual testing.
 - Be constructive in your feedback! Start by saying something postitive.
 - Verify that the changes addresses the correct issues.

When you are done, make sure that correct issues are closed.


# Report

Here you can document your work.


## SQL Injection Protection (2 pts)

Short description of the issue.

One potential area for SQL-injection is in methods where SQL queries are constructed dynamically using string concatenation, such as the `User.loadReadableNotes` method. In this method, the username is directly concatenated into the SQL query without using parameterized queries, making it vulnerable to SQL injection.

### Planning

Explain the mititgation techiniques for SQL injection which are planning to apply.

* Parameterized queries: This is the most effective way to prevent SQL injection. By using parameterized queries, we separate SQL code from user input, ensuring that input is treated strictly as data and cannot alter the structure of the query.

* Input validation and sanitization: Properly validating user inputs helps reduce SQL injection risk. By validating data types, lengths, and formats can stop some simple attacks. For example, we could restrict usernames to alphanumeric characters only to prevent special characters (such as quotes or semicolons) that could be used in an injection attempt. For example, we could enforce a regex pattern like ^[a-zA-Z0-9]+$ to validate that usernames contain only letters and numbers.

* Least-privilege: The application database account should only have the necessary permissions for the required operations. For instance, if the account only needs read access for certain actions, we’ll restrict it from executing delete or update commands. This minimizes the risk if an SQL injection attempt is successful by limiting what the attacker could access or alter.

Input validation is handled in [authentication](#authentication), and least-privilege is handled in [access control](#access-control). 

[Link to issue(s) created](https://git.app.uib.no/Mathias.H.Ness/inshare/-/issues/1) 

### Implementation

Describe any challenges you faced in the implementation.

We needed to fix the query in `User.loadReadableNotes`, and make username a parameterized variable instead of just concatinating it. To do this, we simply change the query from `WHERE u.username = '""" + username + "' AND nup.permission = 'READ'` into `WHERE u.username = ? AND nup.permission = 'READ'`, and let the return statement take in an extra argument `username`. 

[Link to commits which are part of the fix.](https://git.app.uib.no/Mathias.H.Ness/inshare/-/merge_requests/3/diffs?commit_id=c73762b0c07de56bbcf0fb5f2e4de7d6d15aa43d)


### Review

Describe the steps you have taken to ensure that the issue is really fixed.

- Run Zap and SonarQube:
  - In previous analisys with SonarQube, there has been a security warning related to string concatination. This issue is now resolved.
  - Analisys with Zap and SonarQube shows no new security alerts related to the new implementation.
- Automatic test:
  - Verify that UserTest.java passes.
  - This test checks that username is not concatinated direclty into the query. 
- User tests:
  - Checking that a username is not concatinated directly into the query. 
    (e.g. create and login as user `‘ OR ‘1’=’1`, and check that the desktop doesn't view all notes in the database).
  

[Link to merge request with review](https://git.app.uib.no/Mathias.H.Ness/inshare/-/merge_requests/3).


## XSS Protection (3 pts)

Short description of the issue.

The main XSS vulnerability in InShare centers around the content of the notes. Since we allow HTML tags for text formatting, there's a risk that malicious scripts could be within the note content, leading to cross-site scripting attacks. This can happen not only through direct input but also through request tampering, where an attacker manipulates requests to insert harmful scripts. For example, as we saw in the last assignment, a script like `<script>alert("XSS attack");</script>` in note content, would trigger an alert every time the user refreshes the page. 

Although Quill editor provide some built-in sanitization on the frontend, this approach alone is not enough to secure the application. Just relying on frontend sanitization is risky because attackers can buypass it by sending manipulated requests to the backend.

To address this, we need a solution that sanitizes the content of notes before they are displayed, in other words we need to sanitize in the backend. Our approach is to use an HTML sanitizer, such as OWASP AntiSamy, which will strip out any potentially harmful tags or attributes while preserving the allowed HTML formatting.This approach ensures that only safe and approved HTML tags are rendered, protecting against XSS vulnerabilities without removing the intended note formatting.

### Planning

Explain how you plan to mitigate the XSS vulnerability while keeping the formatting functionality.

To migate the XSS vulnerability while preserving formatting functionality, I plan to integrate OWASP AntiSamy into the note content processing workflow. The main goal is to sanitize all HTML content in notes, allowing safe and pre-approved tags while blocking any potentially harmful scripts.

First I'll configure AntiSamy using one of the standard policy files that matches the functionality we need. Slashdot seemed to be the right policy for our use, since it only allows the following HTML tags, and no CSS: `a`, `p`, `div`, `i`, `b`, `em`, `blockquote`, `tt`, `strong`, `br`, `ul`, `ol`, `li`.

When a note is created or updated, AntiSamy will scan and clean the content, based on the policy file. This ensures that the output only contains safe HTML, free from any script or XSS risks. After sanitization, the clean content will be returned as the content os the note.

[Link to issue(s) created](https://git.app.uib.no/Mathias.H.Ness/inshare/-/issues/21).


### Implementation

Describe any challenges you faced in the implementation.

The first challange I faced during the implementation was figuring out how to handle the AntiSamy policy file without downloading it directly into the project. Using an `InputStream` solved the problem by allowing the policy file to be streamed at runtime, simplifying the implementation and minimizing the need for file management.

In the first version of the implementation, I sanitized the content in the `withContent` method. This seemed like a good solution, until we discovered that the `NoteController.createNote` method was not actually sanitizing the content. To fix this, we made the root constructor do the sanitization, since the methods `NoteController.createNote`, `NoteController.updateNote` and `Note.withContent` all will eventually use the root constructor. The [last commit](https://git.app.uib.no/Mathias.H.Ness/inshare/-/merge_requests/11/diffs?commit_id=22958f6a81cb547150e274be64e1ac436eb3cc35) shows which changes I made, and the script below was the test-script that found this exploit.

```js
const csrfToken = document.getElementById('xsrf-token').value;
const noteContent = `<script>alert("xxs!");</script>`;
const noteName = `xss`;
async function xss() {
    await fetch("/note/create", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", 'X-XSRF-TOKEN': csrfToken }, body: new URLSearchParams({
      name: noteName,
      content: noteContent, }),
    });
}
xss();
```

Link to commits which are part of the fix.
- [First fix](https://git.app.uib.no/Mathias.H.Ness/inshare/-/merge_requests/6/diffs?commit_id=1743a1ec78cc576e2f850ac2a945a0ec1658a73b)
- [Last fix](https://git.app.uib.no/Mathias.H.Ness/inshare/-/merge_requests/11/diffs?commit_id=22958f6a81cb547150e274be64e1ac436eb3cc35)

### Review

Describe the steps you have taken to ensure that the issue is really fixed.

To ensure that the XSS vulnerability is effectively mitigated, I took the following steps:

- Run ZAP
  - analisys with Zap show no new security alerts related to the new code
- Run SonarQube
  - Analisys with SonarQube shows no new security alerts related to the new code
User tests:
  - Made a unit test for the `Note` class to verify that it correctly sanitizes input.
  - I manually tested inserting XSS scripts (e.g. `<script>alert("XSS attack");</script>`) into note content to ensure that it doesn't execute. 
  - I have also manually tested that non-malicious note content are being preserved. 
  - I reviewed the AntiSamy Slashdot policy configuration to ensure it allows only safe tags and attributes for text formatting. 
  - To handle cases where the policy file might be missing, I included error handling in the `Note.sanitizeContent` method. 


Link to merge requests with review.
- [First merge request](https://git.app.uib.no/Mathias.H.Ness/inshare/-/merge_requests/6)
- [Final merge request](https://git.app.uib.no/Mathias.H.Ness/inshare/-/merge_requests/11)

## CSRF Protection (2 pts)

The system contains __Cross Site Request Forgery__ vulnerabilities due to missing protection in the form of absent tokens and a "relaxed" approach to flags on cookies. Without proper csrf protection, attackers can exploit a user's session to perform malicious actions.

### Planning

**Identifying the issues**

There is a vulnerability for csrf attacks. The tokens are disabled in `SecurityConfig.java`. This also means no tokens are implemented on requests. We know actions check for authentication and permission but this can be exploited from an external site if a user were to click a link, which seemingly fools the system into thinking it was the user who made the request. Some of the requests use GET requests, this is not wrong in every context but POST requests are generally safer with respect to csrf. Delete note has been identified as especially vulnerable as it is a "state changing" action and it uses a GET requets. What i mean by state changing is that it directly introduces changes to the system when referenced. The show edit form (as an example) also uses GET request, however this only redirects the user to the edit form and to change the note there still has to be sent a POST request with the new content. Inspecting cookies reveals the httponly flag is enabled for the session token, this is good but not sufficient protection alone. Samesite flag is set to "lax" this further limits the safety of GET requests. Secure flag is also disabled.

There is 'a lot' that can be done with the inshare system, for example using https. The fix we introduced to the system however, is a lot simpler but it should mitigate the concerns of csrf vulnerabilites related to 'critical' note actions.

**Issue summary**

- Enable csrf tokens globally in `SecurityConfig.java`
- Change action delete from a GET request to a DELETE request.
- implement csrf tokens for requests.

**CSRF issue (individual steps are split to child items):**

[Link to issue(s)](https://git.app.uib.no/Mathias.H.Ness/inshare/-/issues/2) 

### Implementation

**what was done and what problems did we encounter?**
I first removed the .disable call on the csrf token. This enabled the token globally, but it "broke" the webpage. This problem was fixed by adding `CookieCsrfTokenRepository.withHttpOnlyFalse()`, to allows javascript. Another problem I encountered was the registration site not working. This was related to the request expecting a token, but this token is not sent automatically with this request because the register form was not created with thymeleaf. I concluded that a csrf token was not necessary for the register form as this was a publicly available site. I therefore configured the token with `.ignoringRequestMatchers("/register")`. Another security vulnerability which was identified was the DELETE note action as a GET request. It is considered bad practice to use GET requests on "state changing" requests (as mentioned before). I therefore changed this to a DELETE request and added the csrf token to the request.

The GET request for edits could also be a potential vulnerability. However the backend permission check for this request, makes it so users without write access are redirected back to the dashboard. And if this request was done with someone who has write permission, they would still need to edit the form and a POST request with the new content. This POST request would be stopped if it was a csrf.

**commits**

- adapting the csrf settings [enable](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/5906bda67b77e73fd0b2e3907ffbfa7a521afb1a) [finally adapted correctly](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/eb9899a253a5bc23207cdf6cfc326ec81ea365f5)
- Change delete action from a GET request to a DELETE request. [change to DELETE](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/baba111ba15f66b14e4de8f0c6b265e50b877ddd) [return a reponse](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/eb9899a253a5bc23207cdf6cfc326ec81ea365f5)
- implement csrf tokens for request (the delete action DELETE request) [link](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/253c2343b984a5991e8460c60b5f7a6aca570d17) 

### Review

**Testing csrf**

- Run Zap
  - analisys with Zap show no new security alerts related to the new code
- Run SonarQube
  - Analisys before fix:
  "Make sure disabling Spring Security's CSRF protection is safe here." refering to csrf.disable().
  - Analysis after fix:
  This alert is now only related to the register page, which should be safe without a csrf token.
- User Tests
  - Created a link for deleting a note, the note is not deleted when the link is clicked
  - Ensured normal functionality still works as expected
    - register new users
    - login
    - sharing
    - deleting (the correct way)
    - editing
- Website which tests csrf vulnerability on delete note, Credit: Kristian Elde (Student) [link](https://inshare-malicious-csrf.vercel.app/)

[Link to merge request with review.](https://git.app.uib.no/Mathias.H.Ness/inshare/-/merge_requests/7)


## Authentication Improvement (3 pts)

Short description of the issue.

The primary issue with the current authentication system in InShare, is the weakness around password storage and password strength requirements. Currently, passwords are stored without a key derivation function, which leaves them vulnerable to database attacks/leaks. There is also no requirement for password lengt or complexity, making it easier for users to choose weak passwords that can be easily guessed or brute-forced. By having restrictions on username, where it can only contain letters, numbers and underscores as well as a length check, where it should be between 6 and 20 characters, will secure the application even further.

### Planning

Detail your plan for improving the authentication here.

To improve these authentication related problems, I plan to hashing the passwords before storing them in the database and enforcing stronger password requirements.

1. Install and configure the Argon2 library.
2. Update the code to hash passwords using Argon2 before storage.
3. User tests to ensure passwords are correctly hashed and stored.
4. Implement password and username validation in both backend and frontend.
5. Make the UI respond to the user, if username/password is not in desired patterns.
6. Check both password and username with regex-patterns, where:
    - 6.1. Username should be between 6 and 20 characters, where only letters, numbers and underscores are allowed.
    - 6.2. Password shold be at leat 8 characters, containing at least one uppercase letter, one number and one special character.
7. Write tests to verify that only compliant passwords are accepted. 


[Link to issue(s) created.](https://git.app.uib.no/Mathias.H.Ness/inshare/-/issues/8)

### Implementation

Describe any challenges you faced in the implementation.

There was two challanges I faced during the implementation.

1. Determining the correct regular expression to enforce password strenght requirements. It took some trial and error to ensure that the regex covered all necessary criteria (at least one uppercase letter, one digit and one special character).

2. Implementing the `RegistrationController.register` method to correctly hash the password before storing it and checking that the password and username both match the desired regex pattern. I did also check the regex pattern in frontend at `register.html`.

[Link to all commits which are part of the fix.](https://git.app.uib.no/Mathias.H.Ness/inshare/-/merge_requests/2/commits?commit_id=7e50b17d669b93b067213c30442ae288da79f9ec)

[Link](https://git.app.uib.no/Mathias.H.Ness/inshare/-/merge_requests/2/diffs?commit_id=d3ab8dd9efb7fe20e50a6d68e050076d93cfc0a1#29cd62c615431abe87b2bfe94dceace08ea539b2) to the commit that fixed both forntend and backend regex pattern matching (and tests). 


### Review

Describe the steps you have taken to ensure that the issue is really fixed.

- Run Zap
  - Analisys with Zap show no new security alerts related to the new code
- Run SonarQube
  - Analisys with SonarQube shows no new security alerts related to the new code
- User tests:
  - Manually checked different usernames and passwords to ensure that the implementation makes sure the formatting is correct, and that the user gets the errors as expected. 
  - Verified that the passwords are hashed and stored correctly in the database.
- Unit tests for helper methods
  - Verified that `checkUsernameFormat` and `checkPasswordFormat` enforce the correct rules for usernames and passwords.
- Tested registration flow
  - Registering with valid usernames and passwords.
  - Attempting to register with invalid usernames.
  - Attemting to register with weak passwords.
  - Preventing duplicate usernames. Tests confirm that only valid registrations proceed and passwords are hashed correctly.



[Link to merge request with review.](https://git.app.uib.no/Mathias.H.Ness/inshare/-/merge_requests/2?commit_id=55979032db29a2ac1e6d068f7aa3b88ff920ed0c#39d0edf47f695698608b884b9773e3f0f285a55d)


## Access Control Improvement (4 pts)

Inshare has a flawed and limited Access control model, which can be exploited. There are also bugs which permit users to aquire permissions they don't have, and they can buypass permission checks to perform unauthorized actions due to a lack of backend permission checks.

### Planning

**Identifying the issues**

The current access control model uses an access control model list, which has it's limitations in options for different permissions, it's inefficient and not practical. The author/creator of a resource (note) can choose whom to share it with, but once it's shared, the author has little control over it and it can be shared further. There are no restrictions to who can give whom what permissions either. To summarize, the systemk has many flaws. Only the DELETE action is properly checked at the backend and other actions rely on the UI which is a bad practice. The system also has insecure direct object refrences which can be exploited without permissions, this problem is also related to the lack of backend permission checks.

**Solution**
Remodel the access control model to used a role based system, and ensure permission checks are handled at the backend.

Introducing such a big change to the system, requires some understanding of how the system works and how the components work together. I therefore chose to split the problem into two parts, first do small changes which would help me gain a better understanding of the system. 

Iteration 1: limit sharing to those with write access, perform backend permission checks. Perform these backend checks with a helper method. Following OOP-principles this, this method should still work when the RBAC system is implemented.

Iteration 2: introduce Role based access control, perform backend permission checks, fix flawed UI.

**Issues IT1**
- Limit share access to users with WRITE access
- Ensure permission checks are handled at backend


**RBAC (from assignment notes)**
Plan for the creation of a Role Based Access Control (RBAC) for InShare:

Include a new database schema for the roles and permissions. Remember to set up foreign keys, and add additional constraints where suitable.
The roles should be:

- "owner": Each note has a unique owner. Has read/write/delete permissions. Cannot be revoked, only transferred by the owner themselves.
- "administrator": Has read/write/delete permissions. Can set roles (except owner).
- "editor": Has read/write permissions.
- "reader": Can only read the note.

Plan which methods on the backend have to include checks for permssions, and how this will be coordinated with the UI.
Change the UI so that the sharing mechanism uses the new roles. Include an option to transfer ownership of a note.
How will you determine that the security of the access control mechanism has improved?

**My understanding of the taskdescription** 
Editor and reader is pretty self-explainitory. Admin and owner can share. There can only be one owner. The owner can choose to transfer this ownership, but this means they loose their role as an owner.

[Link to issue(s) created.](https://git.app.uib.no/Mathias.H.Ness/inshare/-/issues/9)

### Implementation

**1st iteration (sharing is limited to write access)**
__done:__

- share button/option removed from from users who does not have write access
- Permissionchecks for all backend notecontroller actions

**RBAC model**

- Impl. RBAC in DB -> `SQLiteConfig.java`. [link](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/5a090a4d308a2a794af4a6e372c9ff5e7ca86649)
- remove old structure in DB -> `SQLiteConfig.java` (Doing later). [link](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/b7238c292acdff43d4e8b72cc36216e9dac59eec)
- update UI [link](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/c616da54af0dd5810bb9089abcf3b6419a0a0382)
- update backend to adapt to new roles. [link Note](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/2b839d4ca5d84a2c101275e587f416af0ad72f99) [link User](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/7fe4988e0f1027dc1c9761b38c0ca1ff14cbeba5)
- enforce backend permission checks on all actions [link](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/85299fdde828dd0f80b003265c6216ca7aca6f63) `::checkPermission` method (based on the already existing permission check in `::delete`) made in IT1 [link](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/3647f78819c93c58384cfde1adf211ef773ac7d8)

**implications**

- the sample db is not compatible with the new stucture
- Changing to a RBAC model is a significant change, which requires many changes accross many different files. It's easy to make a mistake. The changes themselves however was not that difficult once you undestand how the system is constructed. This is partly why i choose to limit sharing to users with write permission first, as a self-exercise.

**Testing the security of AC model**

- Run Zap
  - analisys with Zap show no new security alerts related to the new code
- Run SonarQube
  - Analisys with sonarqube show no new security issues related to new code
- User Tests
  - Every backend note action uses permission checks
  - Users can no longer share with themselves
  - Only owner and admin can share
  - Only owner can transfer ownership
  - It is no longer possible to manually alter urls to gain unauthorized access
  - UI: Only permissitted actions related to a user's role is displayed in the menus
  - Creating new notes, store them in new db structure

### Review

[Link to merge request with review.](https://git.app.uib.no/Mathias.H.Ness/inshare/-/merge_requests/4)

## Logging System Improvement (1 pts)

Security logging is important in software security to detect and respond to security related incidents. Logs provide a traceable flow of significant actions. It's important that we are selective in what we choose to log and make sure to keep the same standards for integrity and data consistency in the log. This way we can trace attacks back to the attacker and identify vulnerabilities.

### Planning

There is very little logging in the inshare system. Logging is important to detect threats, trace them and respond to them.

**Identfying the issues**

Currently in Inshare the only logging is in `Note.java` and `SQLiteConfig.java`. The loggers in the two classes log the events; 'enabling foreign key support', 'load note' and 'load roles'. It is not wrong to log these events, but they are not critical and should not be in focus when there is else where no logging.

**What should be logged (based on slides)**
For extra context I have included some scenarios which I will not be logging in the Inshare system, I denote these with (?). These scenarios are just examples of what could be logged to satisfy requirements from the slides, however, they are not critical wrt. the inshare system and will be overlooked.

- Authentication events
  - Successful Logins: Log successful login events with the.
  - Failed Login Attempts: Log failed attempts to detect potential brute-force attacks. 
  - Logout Events: Track when users log out, this provides a picture of session length.
  - (?)Session Token Generation and Expiration
- Attempted intrusions
  - SQL Injection Attempts: If the system detects suspicious input patterns at backend.
  - Cross-Site Scripting (XSS) Attempts: Log any detected scripts at backend. 
  - Unauthorized Access Attempts: Log instances caught at backend. 
  - (?) Suspicious API Access: Record attempts at request tampering.
- Violations of invariants
  - Data consistency violations: ex, editor tries to delete a note (in this case, related to *unauthorized access attempts*).
- Unusual behaviour
  - (?) Abnormal frequency of notesharing.
- (?) Performance statistics
  - (?) Log loading times. 
  - (?) Log request latency.

- Note Actions, log all actions with the type of action, user involved, and the note.

**All these logging events** should of course avoid violationg any form of user privacy or share sensitive data.

**What are you recommendations for log monitoring and response for InShare?**

If we wanted to deploy inshare in a realistic environment the current (and improved) logging mechanisms should undergo more improvements. Based on defined key security events we want to monitor, these should be logged to an external service where they could be stored (could be stored in the DB, but this would be a some what artifical solution), alternatively a cloud based solution which offers analysis tools. When alerts are then triggered by analysis in the cloud or by some self-integrated analysis system, there should be some pre-defined routines for incident/threat detection response based on the type of alert.

[Link to issue(s) created.](https://git.app.uib.no/Mathias.H.Ness/inshare/-/issues/29)

### Implementation

We chose to stick with the current logging system, but increase the frequency of logging, and focus on security related events. Ideally the logging should be forwarded to an external service (as mentioend). In Inshare we used the `Logger` which logs it to the terminal. The logger provides some options, and in our solution we have used; `Info`, `Warn` and `Error` based on what type of event is being logged.

**What we logged**

`NoteController`
Logged with a helper method which logs the related user.id, the note.id and a message. Also takes a `boolean error` to log info or error
  - Successfull note actions, logged with `.info`
  - Unsuccessfull note actions, logged with `.error`
[link](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/135e157ab4df502c30a28e6bcb61a0ae19c7be11)

`AuthenticationLogger`
A new EventListener class which listens for authentication related events. Logs events with the related user and the timestamp.
  - Successfull login, logged with `.info`
  - Failed login/bad credentials, logged with `.warn`
  - Log out, logged with `.info`
[link](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/48ea379d559db97e429f3599a793aae69defe453)

`Note`
Logs some Note related actions and security breaches. The need for content sanitization at backend might indicate an attempt at xss attack.
  - Log backend sanitization, logged with `.warn`
  - Kept former logging events
[initial logger (oversensitive)](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/783a2d7a6ce235996af6edeacc37add5285fc540)
[new solution: check num errors](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/cebb1d60eb900725c8156100f920414a04cc1888)
[(c2)new solution: exclude p tag error](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/31e07cf3b45b74be2d2f1decf56d6617747b3f02)
[added back some logging which was commented out during user tests](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/783a2d7a6ce235996af6edeacc37add5285fc540)

`RegistrationController`
Log event related to (un)successfull registration events
  - Successfull registration, logged with `.info`
  - Illegal username caught at backend, logged with `.warn`
  - Illegal password caught at backend, logged with `.warn`
  - Unsuccessful due to taken username, logged with `.error`
[link](https://git.app.uib.no/Mathias.H.Ness/inshare/-/commit/f04db72362aa5be299d92b62acf04ed2ff5084f8)

### Review

- Run Zap
  - analisys with Zap show no new security alerts related to the new code
- Run SonarQube
  - Analisys with sonarqube show no new security issues related to new code
- UserTests
  - Tested normal functionality works as expected
    - register
    - login
    - note actions, edit, share, read, delete
  - tested sample actions legal and ilegal is logged
    - note actions
    - passing scripts/ilegal note content (initial solution was oversensitive, decided to form a different approach to the problem, hence two merge requests)
    - registration, successful and unsuccessful
    - Authentication related events, in, out, bad creadentials


[Link to merge request with review.](https://git.app.uib.no/Mathias.H.Ness/inshare/-/merge_requests/8)
[Ling to merge request for with improvements for sanitization logging](https://git.app.uib.no/Mathias.H.Ness/inshare/-/merge_requests/12)
