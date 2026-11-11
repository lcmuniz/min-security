package io.github.lcmuniz.minsecurity;

import java.util.List;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService users;
    private final JwtService jwt;
    private final RefreshTokenStore refreshTokens;

    public AuthService(AuthenticationManager authenticationManager, UserDetailsService users,
                       JwtService jwt, RefreshTokenStore refreshTokens) {
        this.authenticationManager = authenticationManager;
        this.users = users;
        this.jwt = jwt;
        this.refreshTokens = refreshTokens;
    }

    public TokenResponse login(String username, String password) {
        Authentication auth;
        try {
            auth = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(username, password));
        } catch (AuthenticationException e) {
            throw new InvalidCredentialsException();
        }
        return issueTokens(auth.getName(), roles(auth.getAuthorities()));
    }

    /** Exchanges a refresh token for a new token pair; the old refresh token stops working. */
    public TokenResponse refresh(String refreshToken) {
        Claims claims = verifyRefresh(refreshToken);
        String username = claims.getSubject();
        if (!refreshTokens.consume(claims.getId(), username)) {
            throw new InvalidRefreshTokenException();
        }
        UserDetails user;
        try {
            user = users.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            throw new InvalidRefreshTokenException();
        }
        if (!user.isEnabled() || !user.isAccountNonLocked()) {
            throw new InvalidRefreshTokenException();
        }
        // Roles come from the user store, not from the token, so a role change takes effect on refresh.
        return issueTokens(username, roles(user.getAuthorities()));
    }

    /** Revokes the refresh token so it can no longer be used. Access tokens expire on their own. */
    public void logout(String refreshToken, String currentUser) {
        Claims claims = verifyRefresh(refreshToken);
        if (!claims.getSubject().equals(currentUser)) {
            throw new InvalidRefreshTokenException();
        }
        refreshTokens.consume(claims.getId(), currentUser);
    }

    private Claims verifyRefresh(String refreshToken) {
        try {
            return jwt.verify(refreshToken, TokenType.REFRESH);
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidRefreshTokenException();
        }
    }

    private TokenResponse issueTokens(String username, List<String> roles) {
        JwtService.IssuedRefreshToken refresh = jwt.refreshToken(username);
        refreshTokens.save(refresh.id(), username, refresh.expiresAt());
        return new TokenResponse(jwt.accessToken(username, roles), refresh.token(), "Bearer");
    }

    private static List<String> roles(java.util.Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                // Only roles go into the token; other authorities (e.g. FACTOR_PASSWORD) are skipped.
                .filter(a -> a.startsWith("ROLE_"))
                .map(a -> a.substring(5))
                .toList();
    }
}
