# Mandatory assignment 2 – INF226 – 2024

In this assignment you will analyse the security of a
program called *InShare*. The program is a note-writing and
note-sharing program, which runs as an HTTP-based web
application. *InShare* allows users to create, edit, and
share notes with others, as well as manage access
permissions for different users. Your task is to identify
security vulnerabilities in the application, understand
their impact on the security of the system.

You can [find the project on GitLab](https://git.app.uib.no/inf226/inshare),

## Learing outcomes

From the course description:

 - The student understands security issues relating to system development.
 - The student knows software development techniques to avoid security problems.
 - The student can explain the most common weaknesses in software security and how such problems can be mitigated in software.
 - The student can identify common security threats, risks, and attack vectors for software systems.
 - The student knows best practices to defend software systems.
 - The student can assess the security of given source code or application.
 - The student can plan and carry out varied assignments and projects for secure software.
 - The student can develop critical thinking about secure software.

This assignment is an oportunity for you to exercise these skills, and demonstrate your ability.

### Objectives

The primary objectives of this assignment are to:

 - Understand the security implications of common vulnerabilities in web-applications, such as SQL injection, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), and broken access control.
 - Perform a threat modeling exercise to identify the security requirements of the InShare application and its various components.
 - Identify and exploit security vulnerabilities in the codebase to demonstrate their impact.

### Collaboration

Just as on the previous assignment, you can collaborate in groups of up to three
students. The group composition does not have to be the same as on the previous
assignment, but it can. Make sure that each group member is assigned to the
group on MittUiB.

### Deliverables

You should submit a written report on the security of InShare, addressing the
exercises below. Your report must be a PDF file, and remember to include any
code you have written and describe the steps you have taken carefully.
Include precise references to parts of the code with vulnerabilities.

### Structure of the assignment and strategy for solving the exercies

You are recommended to start with creating the functional decomposition of
the program. Read the source code and make sure you understand how the
various parts function and are connected. Then you should go on to providing
the use-case oriented security requirements. Once that is done, try to find
the specific vulnerabilities in Exercise 2, before going back to completing
Exercise 1.

### Running the project

To test and analyze the InShare, you will need to run it locally on
your own machine.

To run the InShare project you will need JDK 17, and Maven installed.
You can either run InShare from a terminal using the commands below,
or use an IDE like VS code with Spring Boot plugins.

`````
 $ git clone https://git.app.uib.no/inf226/24h/inshare.git
 $ cd inshare
 $ mvn spring-boot:run
`````

After launching it successfully, you can visit [http://localhost:8080/](http://localhost:8080/)
to open InShare. This is your local instance, and is backed by an (initially empty) database
located in "sample.db"

### Example database

For your convenience, there is an example database in the repository
which you can use to test your exploits on. There are three users:

 - alice, with password: "password123"
 - bob, with password: "bobpassword"
 - charlie, with password: "hunter2"

The sample database is located in the file `sample.db`, but the
InShare program will read from inshare.db (and create an empty one if it
does not exist). You can at any point replace the current database with the sample
database to reset to a known point:

`````
 $ cp sample.db inshare.db
`````

## Exercise 1: The threat model

In this model you will develop a threat model for Inshare, which will
form the basis for evaluating its security.

### 1.1: Functional decomposition

Provide a detailed functional decomposition of the application. Break
down the major functionalities such as user registration, authentication,
note creation, editing, sharing, and deletion. Make sure to accurately
represent how the different components are connected.

### 1.2: Use cases and security expectations

For each of the use cases below, write out what the security expectations (requirements)
the user(s) could be w.r.t. to the InShare system.

Use Case 1
: A user keeps sensitive notes.

Use Case 2
: A group of users collaborates on a shared note.

Use Case 3
: A single user writes a note shared with several readers.

### 1.3: Security requirements of the system

Elaborate on the security requirements on the interaction between the following components:

- The user
- The dashboard UI running in the client User 
- The dashboard backend function
- The User registration backend
- The authentication / login backend
- The note action viewing/editing/deletion backend
- The note action viewing/editing/deletion front ends


### 1.4: Security assumptions

Define a reasonable set of assumptions about the
adversarial environment in which the InShare application
will be deployed.


## Exercise 2: The security holes

In this exercise you will identify a number of security flaws
in InShare, construct example exploits and explain how

### 2.1: SQL injection

The InShare platform is backed by a SQLite. SQLite is a popular
filebased SQL database, but, like all databases where queries are
passed as strings, injection vulnerabilities can result from
inproper insertion of data.

 a) Locate an area of the code which could result in a SQL injection
    vulnerability.

 b) Test the presence of the SQL injection without harming the data
    or violating the users' privacy by exposing private data.

 c) Devise an exploit which uses SQL injection to read all the
    notes on the server. To demonstrate it on the sample database,
    register a new user, and use the exploit to read all the messages
    of the other users (Alice, Bob and Charlie).

 d) Describe which security requirements from the threat model are
    compromised by this vulnerability.


### 2.2: Cross-Site Scripting

Cross Site Scripting (XSS) is a class of vulnerabilities where data
is confused for JavaScript when it is inserted into HTML pages.

 a) Locate an area of the code which could result in a XSS vulnerability.
    *Hint: The XSS vulnerability in InShare does not arise from an explicit
    string concatenation in the Java source code.*

 b) Test the presence of the XSS without harming the data or violating
    the user' privacy by exposing private data.

 c) Device a specific XSS which allows one a user to create a note
    which is authored by another user. To demonstrate this exploit:

- Log in as Charlie (the attacker in this example) and craft a malicious note and share it with Alice.
- When Alice opens her dashboard, a message with Alice as author, title "Important" and the text "InShare is super-secure!" should be automatically created and shared with Bob.
- Verify that the "Important" message appears in Bob's dashboard and that the author is indeed Alice.
- Make sure that the attack message is deleted, and that the "Important" note is not visible in Alice' dashboard.

 d) Assume that the Dashboard has been updated with a content truncation: Line number 121, which used to read: `<p th:utext="${note.content}"></p>` has been replaced with `<p th:utext="${note.content.length() > 120 ? note.content.substring(0, 120) + '...' : note.content}"></p>`. Modify your exploit so that it works with the new dashboard code.

 e) Describe which security requirements from the threat model are compromised by this vulnerability.


### 2.3: Authentication

Analyse the security of the authentication mechanisms in the application. Does it follow best practises?


### 2.4: Access Control

The InShare application provides basic access control features.
A note can be shared, with our without write and delete access.

 a) What kind of access control model does InShare use?

 b) Which parts of the code checks the permissions to enforce the access
    control? Where is this code executed? Is this how it should be?

 Alice has shared a note with Bob called "Project ideas" with only read access (see the
 sample database).

 c) Demonstrate how Bob can obtain WRITE access to the "Project ideas" note using
    bugs in the access control mechanisms of the program.

 d) (Reset the database so that Bob no longer has WRITE access). Demonstrate how
    Bob can edit "Project ideas" without obtaining WRITE access.



### 2.5: Cross-site request forgery

a) Analyse the posibility of CSRF for each of the actions on note (create, share, edit and delete). Take into account presence of CSRF tokens, flags on cookies and other relevant information.

b) Write a link such that if Alice clicks the link while logged, the "Personal Diary" note is deleted. Discuss how this link could be embedded in an attacker's website to further obfuscate its effect.
