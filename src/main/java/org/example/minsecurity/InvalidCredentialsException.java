package org.example.minsecurity;

public class InvalidCredentialsException extends Throwable {
    public InvalidCredentialsException() {
        super("Invalid credentials");
    }
}
