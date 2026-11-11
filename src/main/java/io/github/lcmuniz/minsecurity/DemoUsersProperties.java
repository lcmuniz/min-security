package io.github.lcmuniz.minsecurity;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Passwords of the two demo users. Override them with environment variables outside local development. */
@ConfigurationProperties("app.demo")
public record DemoUsersProperties(String adminPassword, String userPassword) {

    public DemoUsersProperties {
        if (adminPassword == null || adminPassword.isBlank()) {
            throw new IllegalStateException("app.demo.admin-password must be set");
        }
        if (userPassword == null || userPassword.isBlank()) {
            throw new IllegalStateException("app.demo.user-password must be set");
        }
    }
}
