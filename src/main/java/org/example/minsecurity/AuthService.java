package org.example.minsecurity;

import java.util.Collection;
import java.util.List;
import java.util.Map;

public class AuthService {

    public Map<String, String> login(String username, String password) throws InvalidCredentialsException {
        if ("admin".equals(username) && "admin".equals(password)) {

            Collection<String> roles = List.of("ADMIN", "USER");

            return Map.of(
                    "accessToken", JwtUtil.accessToken("admin", roles),
                    "refreshToken", JwtUtil.refreshToken("admin")
            );
        }
        throw new InvalidCredentialsException();
    }

    public Map<String, String> refresh(String refreshToken) throws InvalidRefreshTokenException {
        if (JwtUtil.isRefresh(refreshToken)) {
            String username = JwtUtil.validate(refreshToken);
            Collection<String> roles = List.of("ADMIN", "USER");
            return Map.of("accessToken", JwtUtil.accessToken(username, roles));
        }
        throw new InvalidRefreshTokenException();
    }
}
