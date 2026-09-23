package com.labs.formauth.authentication;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

// The "built on 2.16" half - pure event-driven counting, zero coupling to
// any provider or filter.
@Component
public class LoginAttemptEventListener {

    private final LoginAttemptTracker tracker;

    public LoginAttemptEventListener(LoginAttemptTracker tracker) {
        this.tracker = tracker;
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        // ONLY genuine wrong-password guesses count as a strike. Counting
        // an AccountLockoutException event too would let an attacker
        // hammering an already-locked account extend their own lockout
        // forever - see Part A's trap.
        if (event.getException() instanceof BadCredentialsException) {
            tracker.recordFailure(event.getAuthentication().getName());
        }
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        tracker.recordSuccess(event.getAuthentication().getName());
    }
}