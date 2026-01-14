package org.example.minsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/public")
    Map<String, String> publicEndpoint() {
        return Map.of("message", "public endpoint");
    }

    @PostMapping("/login")
    Map<String, String> login(@RequestBody Map<String, String> body) {
        if ("admin".equals(body.get("username")) && "admin".equals(body.get("password"))) {

            Collection<String> roles = List.of("ADMIN", "USER");

            return Map.of(
                    "accessToken", JwtUtil.accessToken("admin", roles),
                    "refreshToken", JwtUtil.refreshToken("admin")
            );
        }
        throw new RuntimeException("Invalid credentials");
    }

    @PostMapping("/refresh")
    Map<String, String> refresh(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refreshToken");
        if (JwtUtil.isRefresh(refreshToken)) {
            String username = JwtUtil.validate(refreshToken);
            Collection<String> roles = List.of("ADMIN", "USER");
            return Map.of("accessToken", JwtUtil.accessToken(username, roles));
        }
        throw new RuntimeException("Invalid refresh token");
    }

    @GetMapping("/private")
    Map<String, Object> privateEndpoint(Authentication auth) {
        return Map.of(
                "message", "private endpoint",
                "username", auth.getName(),
                "roles", auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList()
        );
    }

    @PostMapping("/logout")
    Map<String, String> logout() {
        return Map.of("message", "logout");
    }

}
