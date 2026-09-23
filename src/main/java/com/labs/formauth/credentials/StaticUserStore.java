package com.labs.formauth.credentials;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * TOGGLE-ONLY. Not wired into Spring by default - LabUserDetailsService is
 * the active bean. This class exists solely to show the raw contract with
 * ZERO convenience classes: no InMemoryUserDetailsManager, just a Map and
 * two interfaces implemented by hand.
 *
 * To run this instead: comment out @Configuration on LabUserDetailsService,
 * uncomment it here. Only one UserDetailsService bean can exist at a time.
 */
@Configuration
public class StaticUserStore implements UserDetailsService {

    // In a real hand-rolled store, this would be a pre-encoded hash pasted
    // in once, or fetched from wherever. The point: loadUserByUsername()
    // never encodes anything - it only ever returns what's already stored.
    private static final Map<String, RawUser> USERS = Map.of(
            "alice", new RawUser("alice", "{noop}password123", false, false),
            "bob",   new RawUser("bob",   "{noop}password123", true, false)
    );

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // This IS the entire contract. Exactly two outcomes are allowed:
        // a populated UserDetails, or this exception. Nothing else.
        RawUser found = USERS.get(username);
        if (found == null) {
            throw new UsernameNotFoundException("No such user: " + username);
        }
        return found.toUserDetails();
    }

    private record RawUser(String username, String encodedPassword, boolean locked, boolean disabled) {
        UserDetails toUserDetails() {
            return new UserDetails() {
                @Override public String getUsername() { return username; }
                @Override public String getPassword() { return encodedPassword; }
                @Override public Collection<? extends GrantedAuthority> getAuthorities() {
                    return List.of(new SimpleGrantedAuthority("ROLE_USER"));
                }
                @Override public boolean isAccountNonExpired() { return true; }
                @Override public boolean isAccountNonLocked() { return !locked; }
                @Override public boolean isCredentialsNonExpired() { return true; }
                @Override public boolean isEnabled() { return !disabled; }
            };
        }
    }
}