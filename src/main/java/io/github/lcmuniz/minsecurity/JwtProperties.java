package io.github.lcmuniz.minsecurity;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * JWT settings.
 *
 * @param secret     Base64-encoded HMAC key (at least 256 bits). When blank, a random key is generated
 *                   at startup, so tokens do not survive a restart and cannot be shared between instances.
 * @param issuer     value of the {@code iss} claim, checked on every token
 * @param accessTtl  lifetime of access tokens
 * @param refreshTtl lifetime of refresh tokens
 */
@ConfigurationProperties("app.jwt")
public record JwtProperties(String secret, String issuer, Duration accessTtl, Duration refreshTtl) {

    public JwtProperties {
        if (issuer == null || issuer.isBlank()) {
            issuer = "min-security";
        }
        if (accessTtl == null) {
            accessTtl = Duration.ofMinutes(15);
        }
        if (refreshTtl == null) {
            refreshTtl = Duration.ofDays(1);
        }
    }
}
