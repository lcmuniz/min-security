package org.example.minsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    private final AuthService loginService = new AuthService();

    @GetMapping("/public")
    Map<String, String> publicEndpoint() {
        return Map.of("message", "public endpoint");
    }

    @PostMapping("/login")
    Map<String, String> login(@RequestBody Map<String, String> body) throws InvalidCredentialsException {
        return loginService.login(body.get("username"), body.get("password"));
    }

    @PostMapping("/refresh")
    Map<String, String> refresh(@RequestBody Map<String, String> body) throws InvalidRefreshTokenException {
        return loginService.refresh(body.get("refreshToken"));
    }

    @GetMapping("/private")
    Map<String, Object> privateEndpoint(Authentication auth) {
        User user = User.of(auth);
        return Map.of(
                "message", "private endpoint",
                "username", user.getName(),
                "roles", user.getRoles()
        );
    }

    @PostMapping("/logout")
    Map<String, String> logout() {
        return Map.of("message", "logout");
    }

}
