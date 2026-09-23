# Topic 2.17 — Custom lockout/throttling, built on 2.16

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** BCrypt (2.5) already imposes a real, deliberate cost on every password check — but that cost is fixed and identical whether the guess is right or wrong. Against a determined attacker running many parallel requests, or against a weak/common password, per-attempt cost alone isn't enough. What's actually needed is something that **counts** wrong attempts per account and, past a threshold, refuses to even *try* the password for a while — not just "reject it after checking," but skip the check entirely, since running BCrypt on every one of an attacker's guesses defeats the point of throttling.

**☕ API Mapping — this is exactly what Topic 2.16 was built for:** counting is pure event-driven bookkeeping (`@EventListener` on `AbstractAuthenticationFailureEvent`/`AuthenticationSuccessEvent`), completely decoupled from the security machinery itself. Enforcement is a new `AuthenticationProvider` (2.3's architecture again), placed **first** in the provider list, so it gets the first word on every attempt.

---

**🌍 Real World:** For the throttling to actually save the BCrypt cost, the check has to happen *before* any password comparison — and it has to produce a **hard stop**, not a "try the next provider" situation, or `DaoAuthenticationProvider` would still run right after it.

**☕ API Mapping — reusing two exact mechanisms from 2.3:** the provider returns `null` (abstains, exactly like `BackupCredentialsAuthenticationProvider`) when the account isn't currently locked, letting `DaoAuthenticationProvider` proceed normally. When it *is* locked, it throws a custom exception extending `LockedException` — an `AccountStatusException` subtype — which triggers `ProviderManager`'s fast-path rethrow, stopping the entire chain immediately, exactly like a genuinely locked account (2.4's `bob`) already does.

**Deeper mechanism, closing 2.16's exact loop:** `ProviderManager`'s fast-path check is a plain Java `catch (AccountStatusException ex)` — ordinary `instanceof` semantics, so a **subclass** is caught correctly. `DefaultAuthenticationEventPublisher`'s mapping table, from Topic 2.16, uses **exact class equality** — a subclass is *not* matched. Same exception hierarchy, two completely different matching rules in two different places. Without an explicit `setAdditionalExceptionMappings(...)` entry, this custom lockout would stop the provider chain correctly but produce **zero audit events** — silently defeating the very auditing system built one topic ago, for an event that arguably matters *more* than an ordinary bad password.

**⚠️ The trap this design has to actively avoid:** if the failure-counting listener increments on *every* failure event indiscriminately, then an attacker who keeps hammering an already-locked account would keep re-triggering "failures," extending their own lockout window forever with no way for anyone to reset it. The listener has to distinguish "a genuine new wrong-password guess" from "the lockout mechanism itself reporting that it fired" — counting only the former.

**How to observe this directly:** Part B times a blocked, locked-out attempt against a normal password check to prove BCrypt genuinely never ran, and reproduces the exact-match audit gap on this project's own new exception before fixing it.

| Real-world question | Mechanism |
|---|---|
| Where does counting happen? | Decoupled `@EventListener`s (2.16), reacting only to genuine `BadCredentialsException` |
| Where does enforcement happen, and when? | A new provider, first in the list, throwing before password comparison ever runs |
| Does a locked-out attempt reach `PasswordEncoder.matches()`? | No — that's the actual throttling benefit, timed directly in the lab |
| Does the lockout stop the provider chain? | Yes — `instanceof AccountStatusException`, subclass-aware |
| Does the lockout get audited? | Only if explicitly mapped — exact-class matching, not subclass-aware |

---

## Part B — Lab

**Modules touched:** `authentication/` (extends 2.3's and 2.16's files directly)

### API surface covered this topic

| API | Purpose |
|---|---|
| `AuthenticationProvider` (custom) | Placed first — checks lockout state before any provider gets a turn |
| Returning `null` vs. throwing (2.3's semantics) | Abstain vs. hard-stop the chain |
| `LockedException` subclassing | Inherits `AccountStatusException` fast-path behavior for free |
| `@EventListener` on `AbstractAuthenticationFailureEvent` / `AuthenticationSuccessEvent` | Pure counting, no coupling to providers or filters |
| `DefaultAuthenticationEventPublisher.setAdditionalExceptionMappings(Map)` | Closes 2.16's exact-match gap for the new custom exception |

### `src/main/java/com/labs/formauth/authentication/AccountLockoutException.java`
```java
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
```

### `src/main/java/com/labs/formauth/authentication/LoginAttemptTracker.java`
```java
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
```

### `src/main/java/com/labs/formauth/authentication/LoginAttemptEventListener.java`
```java
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
```

### `src/main/java/com/labs/formauth/authentication/LoginAttemptGuardAuthenticationProvider.java`
```java
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
```

### `src/main/java/com/labs/formauth/authentication/AuthenticationManagerConfig.java` (modified — the 2.3/2.16 file)
```java
package com.labs.formauth.authentication;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Map;

@Configuration
public class AuthenticationManagerConfig {

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService,
                                                                PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public LoginAttemptGuardAuthenticationProvider loginAttemptGuardAuthenticationProvider(LoginAttemptTracker tracker) {
        return new LoginAttemptGuardAuthenticationProvider(tracker);
    }

    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        DefaultAuthenticationEventPublisher publisher = new DefaultAuthenticationEventPublisher(applicationEventPublisher);

        // THE FIX foreshadowed in Topic 2.16: exact-class matching means
        // AccountLockoutException (a LockedException SUBCLASS) would
        // otherwise never produce an audit event at all.
        publisher.setAdditionalExceptionMappings(Map.of(
                AccountLockoutException.class, AuthenticationFailureLockedEvent.class
        ));
        return publisher;
    }

    @Bean
    public AuthenticationManager authenticationManager(LoginAttemptGuardAuthenticationProvider loginAttemptGuardAuthenticationProvider,
                                                         DaoAuthenticationProvider daoAuthenticationProvider,
                                                         BackupCredentialsAuthenticationProvider backupProvider,
                                                         AuthenticationEventPublisher authenticationEventPublisher) {
        // ORDER MATTERS (Topic 2.3): the guard goes FIRST, so a locked
        // account never reaches Dao's PasswordEncoder.matches() at all.
        ProviderManager manager = new ProviderManager(
                List.of(loginAttemptGuardAuthenticationProvider, daoAuthenticationProvider, backupProvider));
        manager.setEraseCredentialsAfterAuthentication(true);
        manager.setAuthenticationEventPublisher(authenticationEventPublisher);
        return manager;
    }
}
```

**No change needed to `LabAuthenticationFailureHandler` (2.7/2.14).** It already has an `instanceof LockedException` branch redirecting to the generic `/login?error` — and because `AccountLockoutException` *is* a `LockedException`, ordinary Java polymorphism routes it there automatically. This is deliberate, not incidental: a lockout triggered by too many attempts fires from a **pre**-password check, exactly like a statically locked account (2.4's `bob`) — so 2.7's original safety reasoning ("don't reveal account-state to someone who hasn't proven the password") applies here without a single line changed.

### Run it

```
mvn spring-boot:run
```
```
T=$(curl -s http://localhost:8081/login | grep -oP '(?<=name="_csrf" value=")[^"]*')
for i in 1 2 3; do
  curl -s -X POST http://localhost:8081/perform_login -d "user=alice&pass=WRONG&_csrf=$T" -o /dev/null -w "attempt $i: %{http_code}\n"
done
```
Console, after the third:
```
[2.16] AUDIT FAILURE - principal=alice, exception=BadCredentialsException, message=Bad credentials
[2.17] recordFailure - alice failureCount=3, NOW LOCKED until ...
```

**Fourth attempt — with the CORRECT password:**
```
time curl -s -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123&_csrf=$T" -o /dev/null -w "%{http_code}\n"
```
**Expected:** rejected (`302` to `/login?error`), console shows `[2.17] BLOCKED before password check`, and the `time` output is near-instant — compare it against Topic 2.5's own BCrypt cost measurements. A correct password was supplied and never even reached `PasswordEncoder.matches()`.

### Contrast experiment — reproduce 2.16's foreshadowed gap on this exact exception

Comment out the `.setAdditionalExceptionMappings(...)` block, restart, repeat the lockout sequence through the fourth (blocked) attempt.

**Expected:** `[2.17] BLOCKED before password check` still prints — the enforcement works perfectly — but **no `[2.16] AUDIT FAILURE` line appears for it at all.** Meanwhile, rerun three fresh wrong-password attempts against a *different* account (e.g., `carol`) in the same run — those still correctly produce `[2.16] AUDIT FAILURE ... BadCredentialsException`, proving the gap is specific to the unmapped custom exception, not a general breakage. Restore the mapping once confirmed.

### Try it yourself

1. Lock out `breakglass` the same way (three wrong passwords against `user=breakglass`). Confirm the tracker protects it identically — it has nothing to do with `UserDetailsService` at all, since the guard runs before either provider that would normally handle that account.
2. Rack up two failures against alice, then log in *correctly*. Confirm `[2.17] recordSuccess` fires and clears the history — then submit one wrong password afterward and confirm the counter restarts at `failureCount=1`, not `3`.
3. Temporarily remove the `instanceof BadCredentialsException` check in `LoginAttemptEventListener` (count every failure event, including lockout ones). Lock an account, then keep submitting wrong passwords against it every couple of seconds past the original 10-second window. Does the lockout ever actually expire, or does it keep extending? This is Part A's warned-about trap, made real.

### Delta

**Added:** `authentication/AccountLockoutException.java`, `authentication/LoginAttemptTracker.java`, `authentication/LoginAttemptEventListener.java`, `authentication/LoginAttemptGuardAuthenticationProvider.java`
**Modified:** `authentication/AuthenticationManagerConfig.java` (new provider registered first, exception mapping added)