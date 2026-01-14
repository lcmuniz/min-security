package org.example.minsecurity;

import org.springframework.web.bind.annotation.*;

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
            return Map.of(
                    "accessToken", JwtUtil.accessToken("admin"),
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
            return Map.of("accessToken", JwtUtil.accessToken(username));
        }
        throw new RuntimeException("Invalid refresh token");
    }

    @GetMapping("/private")
    Map<String, String> privateEndpoint() {
        return Map.of("message", "private endpoint");
    }

    @PostMapping("/logout")
    Map<String, String> logout() {
        return Map.of("message", "logout");
    }

}
