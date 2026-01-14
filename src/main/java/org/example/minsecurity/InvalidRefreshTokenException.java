package org.example.minsecurity;

public class InvalidRefreshTokenException extends Throwable {
    public InvalidRefreshTokenException() {
        super("Invalid refresh token");
    }
}
