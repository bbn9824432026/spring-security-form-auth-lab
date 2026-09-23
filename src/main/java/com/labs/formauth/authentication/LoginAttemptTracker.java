package com.labs.formauth.authentication;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

// In-memory only, per this course's convention. A restart clears every
// lockout; a real multi-instance deployment needs this shared (same
// caveat as SessionRegistry, Topic 2.14).
@Component
public class LoginAttemptTracker {

    private static final int MAX_ATTEMPTS = 3;
    private static final Duration LOCKOUT_DURATION = Duration.ofSeconds(10);

    private record AttemptRecord(int failureCount, Instant lockedUntil) {}

    private final ConcurrentHashMap<String, AttemptRecord> attempts = new ConcurrentHashMap<>();

    public void recordFailure(String username) {
        attempts.compute(username, (user, existing) -> {
            int newCount = (existing == null ? 0 : existing.failureCount()) + 1;
            Instant lockedUntil = (newCount >= MAX_ATTEMPTS) ? Instant.now().plus(LOCKOUT_DURATION) : null;
            System.out.println("[2.17] recordFailure - " + username + " failureCount=" + newCount
                    + (lockedUntil != null ? ", NOW LOCKED until " + lockedUntil : ""));
            return new AttemptRecord(newCount, lockedUntil);
        });
    }

    public void recordSuccess(String username) {
        if (attempts.remove(username) != null) {
            System.out.println("[2.17] recordSuccess - cleared attempt history for " + username);
        }
    }

    public boolean isLocked(String username) {
        AttemptRecord record = attempts.get(username);
        return record != null && record.lockedUntil() != null && Instant.now().isBefore(record.lockedUntil());
    }

    public long secondsRemaining(String username) {
        AttemptRecord record = attempts.get(username);
        if (record == null || record.lockedUntil() == null) return 0;
        return Math.max(0, Duration.between(Instant.now(), record.lockedUntil()).toSeconds());
    }
}