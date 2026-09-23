package com.labs.formauth.authentication;

import org.springframework.security.authentication.LockedException;

// Deliberately extends LockedException (an AccountStatusException subtype)
// so ProviderManager's fast-path check (instanceof, Topic 2.3) stops the
// chain immediately, exactly like a genuinely locked account.
public class AccountLockoutException extends LockedException {
    public AccountLockoutException(String message) {
        super(message);
    }
}