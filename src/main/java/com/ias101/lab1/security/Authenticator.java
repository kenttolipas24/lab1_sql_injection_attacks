package com.ias101.lab1.security;

import com.ias101.lab1.database.util.DBUtil;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.regex.Pattern;

/**
 * Authentication class for user validation
 */
public class Authenticator {
    /**
     * Regex pattern to allow only alphanumeric usernames (prevents SQL injection)
     */
    private static final Pattern SAFE_USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_]+$");

    /**
     * Authenticates a user by checking username and password against the database
     *
     * @param username The username to authenticate
     * @param password The password to authenticate
     * @return boolean Returns true if authentication is successful, false otherwise
     * @throws RuntimeException if there is a SQL error during authentication
     */
    public static boolean authenticateUser(String username, String password) {
        // Ensure username and password are not null or empty
        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Username and password cannot be empty.");
        }

        // Validate username to allow only safe characters
        if (!isValidUsername(username)) {
            throw new IllegalArgumentException("Invalid username format.");
        }

        // Escape single quotes to prevent SQL injection
        username = sanitizeInput(username);
        password = sanitizeInput(password);

        String query = "SELECT COUNT(*) FROM user_data WHERE username = '" + username + "' AND password = '" + password + "'";

        try (Connection conn = DBUtil.connect("jdbc:sqlite:src/main/resources/database/sample.db", "root", "root");
             Statement statement = conn.createStatement();
             ResultSet rs = statement.executeQuery(query)) {

            return rs.next() && rs.getInt(1) > 0; // Check if user exists
        } catch (SQLException e) {
            throw new RuntimeException("Database error during authentication", e);
        }
    }

    /**
     * Ensures username only contains allowed characters to prevent SQL injection.
     *
     * @param username The username to check
     * @return true if username is safe, false otherwise
     */
    private static boolean isValidUsername(String username) {
        return SAFE_USERNAME_PATTERN.matcher(username).matches();
    }

    /**
     * Sanitizes input by escaping single quotes and trimming unnecessary spaces.
     *
     * @param input The string to sanitize
     * @return The sanitized string
     */
    private static String sanitizeInput(String input) {
        return input.trim().replace("'", "''");
    }
}