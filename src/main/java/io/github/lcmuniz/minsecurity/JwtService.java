package io.github.lcmuniz.minsecurity;

import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/** Issues and verifies HS256-signed JWTs. */
@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);
    static final String TYPE_CLAIM = "typ";
    static final String ROLES_CLAIM = "roles";

    private final SecretKey key;
    private final JwtProperties props;
    private final Clock clock;

    public JwtService(JwtProperties props, Clock clock) {
        this.props = props;
        this.clock = clock;
        this.key = buildKey(props.secret());
    }

    private static SecretKey buildKey(String secret) {
        if (secret == null || secret.isBlank()) {
            log.warn("app.jwt.secret is not set: using a random key; tokens will be invalid after a restart");
            return Jwts.SIG.HS256.key().build();
        }
        byte[] bytes = Base64.getDecoder().decode(secret.trim());
        if (bytes.length < 32) {
            throw new IllegalStateException("app.jwt.secret must be a Base64 value of at least 32 bytes");
        }
        return Keys.hmacShaKeyFor(bytes);
    }

    public String accessToken(String username, Collection<String> roles) {
        return build(username, TokenType.ACCESS, props.accessTtl().toSeconds())
                .claim(ROLES_CLAIM, List.copyOf(roles))
                .compact();
    }

    public IssuedRefreshToken refreshToken(String username) {
        String id = UUID.randomUUID().toString();
        Instant expiresAt = clock.instant().plus(props.refreshTtl());
        String token = build(username, TokenType.REFRESH, props.refreshTtl().toSeconds()).id(id).compact();
        return new IssuedRefreshToken(token, id, expiresAt);
    }

    private io.jsonwebtoken.JwtBuilder build(String username, TokenType type, long ttlSeconds) {
        Instant now = clock.instant();
        return Jwts.builder()
                .issuer(props.issuer())
                .subject(username)
                .claim(TYPE_CLAIM, type.name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(ttlSeconds)))
                .signWith(key, Jwts.SIG.HS256);
    }

    /**
     * Verifies signature, expiry, issuer and token type.
     *
     * @throws JwtException if the token is invalid for any reason
     */
    public Claims verify(String token, TokenType expected) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .requireIssuer(props.issuer())
                .clock(() -> Date.from(clock.instant()))
                .build()
                .parseSignedClaims(token)
                .getPayload();
        if (!expected.name().equals(claims.get(TYPE_CLAIM, String.class))) {
            throw new JwtException("Unexpected token type");
        }
        if (claims.getSubject() == null || claims.getSubject().isBlank()) {
            throw new JwtException("Missing subject");
        }
        return claims;
    }

    public record IssuedRefreshToken(String token, String id, Instant expiresAt) {
    }
}
