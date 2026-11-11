package io.github.lcmuniz.minsecurity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.util.List;

import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;

class JwtServiceTests {

    private static final String SECRET = ApiIntegrationTests.SECRET;

    private final JwtService jwt = new JwtService(new JwtProperties(SECRET, null, null, null), Clock.systemUTC());

    @Test
    void accessTokenRoundTrip() {
        var claims = jwt.verify(jwt.accessToken("alice", List.of("USER")), TokenType.ACCESS);
        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.get("roles", List.class)).containsExactly("USER");
    }

    @Test
    void rejectsWrongTokenType() {
        String refresh = jwt.refreshToken("alice").token();
        assertThatThrownBy(() -> jwt.verify(refresh, TokenType.ACCESS)).isInstanceOf(JwtException.class);
        String access = jwt.accessToken("alice", List.of());
        assertThatThrownBy(() -> jwt.verify(access, TokenType.REFRESH)).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsOtherIssuer() {
        var other = new JwtService(new JwtProperties(SECRET, "someone-else", null, null), Clock.systemUTC());
        String token = other.accessToken("alice", List.of());
        assertThatThrownBy(() -> jwt.verify(token, TokenType.ACCESS)).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsShortSecret() {
        assertThatThrownBy(() -> new JwtService(new JwtProperties("c2hvcnQ=", null, null, null), Clock.systemUTC()))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void randomKeyWhenSecretIsBlank() {
        var a = new JwtService(new JwtProperties("", null, null, null), Clock.systemUTC());
        var b = new JwtService(new JwtProperties("", null, null, null), Clock.systemUTC());
        String token = a.accessToken("alice", List.of());
        assertThatThrownBy(() -> b.verify(token, TokenType.ACCESS)).isInstanceOf(JwtException.class);
    }
}
