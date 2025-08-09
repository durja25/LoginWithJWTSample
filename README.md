# Spring Security Project 

## Project Description
This project demonstrates the implementation of Spring Security, including:
- Login using JWT token generation 
- User Signup with Mail verification
- User email verification flow (send verification code, verify user)
- Fetch authenticated user details
- Role-based access control (RBAC)
- Password encryption using BCrypt

## Prerequisites
Before running the application, ensure you have the following installed:

- Java Development Kit (JDK) 8 or newer
- Maven
- Supabase database (With Table format)
- Postman (for testing endpoints)

## Technologies
- Spring Boot 3.0
- Spring Security
- JSON Web Tokens (JWT)
- BCrypt
- Maven
- postgres Supabase database

## How to Run
1. Clone the repository: `git clone https://github.com/gkamble/loginViaJWT.git`
2. Navigate to the project directory: `cd loginViaJWT`
3. Run the Spring Boot application: `./mvnw spring-boot:run`
4. Open Postman and import the `LoginViaJWT.postman_collection.json` file.
5. Run the tests in Postman to verify the endpoints.