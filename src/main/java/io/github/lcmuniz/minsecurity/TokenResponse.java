package io.github.lcmuniz.minsecurity;

public record TokenResponse(String accessToken, String refreshToken, String tokenType) {
}
