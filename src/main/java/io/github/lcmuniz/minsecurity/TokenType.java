package io.github.lcmuniz.minsecurity;

/** Value of the {@code typ} claim, so an access token can never be used as a refresh token or vice versa. */
public enum TokenType {
    ACCESS, REFRESH
}
