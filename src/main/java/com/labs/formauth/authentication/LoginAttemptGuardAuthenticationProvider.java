package com.labs.formauth.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

// Placed FIRST in the provider list. Runs before DaoAuthenticationProvider -
// meaning a locked-out attempt never reaches PasswordEncoder.matches() at
// all. This IS the throttling benefit: the cost is skipped, not just
// "paid and then rejected."
public class LoginAttemptGuardAuthenticationProvider implements AuthenticationProvider {

    private final LoginAttemptTracker tracker;

    public LoginAttemptGuardAuthenticationProvider(LoginAttemptTracker tracker) {
        this.tracker = tracker;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();

        if (tracker.isLocked(username)) {
            long seconds = tracker.secondsRemaining(username);
            System.out.println("[2.17] BLOCKED before password check - " + username
                    + " locked for " + seconds + " more seconds");
            throw new AccountLockoutException("Too many failed attempts. Try again in " + seconds + "s.");
        }

        // Not locked - ABSTAIN, same null-return semantic as
        // BackupCredentialsAuthenticationProvider (Topic 2.3).
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}