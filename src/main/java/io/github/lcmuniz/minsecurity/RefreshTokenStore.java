package io.github.lcmuniz.minsecurity;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

/**
 * Keeps the ids of refresh tokens that are still valid, so a refresh token can be used only once
 * (rotation) and can be revoked on logout.
 *
 * <p>In-memory on purpose to keep the demo dependency-free; a real deployment would use Redis or a
 * database so that every instance sees the same state.
 */
@Component
public class RefreshTokenStore {

    private final Map<String, Entry> active = new ConcurrentHashMap<>();
    private final Clock clock;

    public RefreshTokenStore(Clock clock) {
        this.clock = clock;
    }

    public void save(String id, String username, Instant expiresAt) {
        purgeExpired();
        active.put(id, new Entry(username, expiresAt));
    }

    /** Removes the token id and returns true only if it was active and belonged to {@code username}. */
    public boolean consume(String id, String username) {
        if (id == null) {
            return false;
        }
        Entry entry = active.remove(id);
        return entry != null && entry.username().equals(username) && entry.expiresAt().isAfter(clock.instant());
    }

    private void purgeExpired() {
        Instant now = clock.instant();
        active.values().removeIf(e -> !e.expiresAt().isAfter(now));
    }

    private record Entry(String username, Instant expiresAt) {
    }
}
