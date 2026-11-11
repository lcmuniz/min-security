package io.github.lcmuniz.minsecurity;

import java.util.List;
import java.util.Map;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ApiController {

    private final AuthService auth;

    public ApiController(AuthService auth) {
        this.auth = auth;
    }

    @GetMapping("/public")
    Map<String, String> publicEndpoint() {
        return Map.of("message", "public endpoint");
    }

    @PostMapping("/login")
    TokenResponse login(@Valid @RequestBody LoginRequest body) {
        return auth.login(body.username(), body.password());
    }

    @PostMapping("/refresh")
    TokenResponse refresh(@Valid @RequestBody RefreshRequest body) {
        return auth.refresh(body.refreshToken());
    }

    @GetMapping("/private")
    Map<String, Object> privateEndpoint(Authentication authentication) {
        List<String> roles = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
        return Map.of("message", "private endpoint", "username", authentication.getName(), "roles", roles);
    }

    @GetMapping("/admin")
    Map<String, String> adminEndpoint(Authentication authentication) {
        return Map.of("message", "admin endpoint", "username", authentication.getName());
    }

    @PostMapping("/logout")
    ResponseEntity<Void> logout(@Valid @RequestBody RefreshRequest body, Authentication authentication) {
        auth.logout(body.refreshToken(), authentication.getName());
        return ResponseEntity.noContent().build();
    }
}
