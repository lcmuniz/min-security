package io.github.lcmuniz.minsecurity;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates requests that carry {@code Authorization: Bearer <access token>}.
 *
 * <p>An invalid, expired or wrong-type token is simply ignored: the request continues unauthenticated,
 * so public endpoints still work and protected ones answer 401 through the entry point.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String PREFIX = "Bearer ";
    private final JwtService jwt;

    public JwtAuthenticationFilter(JwtService jwt) {
        this.jwt = jwt;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.regionMatches(true, 0, PREFIX, 0, PREFIX.length())) {
            try {
                Claims claims = jwt.verify(header.substring(PREFIX.length()).trim(), TokenType.ACCESS);
                var authorities = roles(claims).stream()
                        .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                        .toList();
                var auth = UsernamePasswordAuthenticationToken.authenticated(claims.getSubject(), null, authorities);
                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (JwtException | IllegalArgumentException e) {
                SecurityContextHolder.clearContext();
            }
        }
        chain.doFilter(request, response);
    }

    private static List<String> roles(Claims claims) {
        Object raw = claims.get(JwtService.ROLES_CLAIM);
        if (raw instanceof Collection<?> c) {
            return c.stream().filter(String.class::isInstance).map(String.class::cast).toList();
        }
        return List.of();
    }
}
