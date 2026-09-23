package com.labs.formauth.authentication;

import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// STATIC, in-memory - no real database, matching this course's convention.
// Demonstrates the PersistentTokenRepository CONTRACT and the rotation /
// theft-detection behavior it enables. A real system would back this with
// an actual table.
public class InMemoryPersistentTokenRepository implements PersistentTokenRepository {

    private final Map<String, PersistentRememberMeToken> tokensBySeries = new ConcurrentHashMap<>();

    @Override
    public void createNewToken(PersistentRememberMeToken token) {
        System.out.println("[2.15] createNewToken - series=" + token.getSeries()
                + ", username=" + token.getUsername());
        tokensBySeries.put(token.getSeries(), token);
    }

    @Override
    public void updateToken(String series, String tokenValue, Date lastUsed) {
        PersistentRememberMeToken existing = tokensBySeries.get(series);
        if (existing == null) return;
        // THIS is the rotation from Part A - same series, brand-new token,
        // on every single successful remember-me authentication.
        System.out.println("[2.15] updateToken (ROTATION) - series=" + series + ", newToken=" + tokenValue);
        tokensBySeries.put(series, new PersistentRememberMeToken(
                existing.getUsername(), series, tokenValue, lastUsed));
    }

    @Override
    public PersistentRememberMeToken getTokenForSeries(String seriesId) {
        return tokensBySeries.get(seriesId);
    }

    @Override
    public void removeUserTokens(String username) {
        // THIS is the theft-response - wipes EVERY token for the account,
        // not just the offending one.
        System.out.println("[2.15] removeUserTokens (THEFT DETECTED or logout) - username=" + username);
        tokensBySeries.values().removeIf(t -> t.getUsername().equals(username));
    }
}