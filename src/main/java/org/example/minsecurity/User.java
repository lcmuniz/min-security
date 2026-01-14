package org.example.minsecurity;

import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

public class User {
    private final Authentication auth;

    private User(Authentication auth) {
        this.auth = auth;
    }

    public static User of(Authentication auth) {
        return new User(auth);
    }

    public String getName() {
        return auth.getName();
    }

    public List<String> getRoles() {
        return auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
    }
}
