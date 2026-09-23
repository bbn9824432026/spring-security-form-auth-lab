package com.labs.formauth.authentication;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

// Deliberately knows NOTHING about UsernamePasswordAuthenticationFilter,
// DaoAuthenticationProvider, or ProviderManager - only reacts to events.
// This is what should have been doing the audit work since Topic 2.7,
// instead of a println sitting inside a response-writing handler.
@Component
public class AuthenticationAuditListener {

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        System.out.println("[2.16] AUDIT SUCCESS - principal=" + event.getAuthentication().getName()
                + ", authorities=" + event.getAuthentication().getAuthorities());
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        System.out.println("[2.16] AUDIT FAILURE - principal=" + event.getAuthentication().getName()
                + ", exception=" + event.getException().getClass().getSimpleName()
                + ", message=" + event.getException().getMessage());
    }
}