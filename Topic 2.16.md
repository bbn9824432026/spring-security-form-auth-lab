# Topic 2.16 — Authentication events

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** Since Topic 2.2, every audit trail in this project has been a `System.out.println` sitting *directly inside* the security machinery itself — inside a filter, inside a failure handler, inside a provider. That means the code responsible for checking a password is also the code responsible for deciding how that check gets logged. In a real system, auditing, metrics, SIEM ingestion, and alerting are separate concerns with separate consumers — coupling them into the authentication path means every new thing that wants to know about a login requires touching security code directly.

**☕ API Mapping:** Spring's own general event infrastructure — `ApplicationEventPublisher` / `@EventListener` — decoupled by a specific adapter for this domain: `AuthenticationEventPublisher`. Its default implementation, `DefaultAuthenticationEventPublisher`, is called from exactly one place: **inside `ProviderManager`** — the same object from Topic 2.3 — right after the provider-iteration loop concludes, on both the success path and the failure path.

---

**🌍 Real World:** Not every kind of failure is equally worth the same treatment — a bad password and a locked account are different events worth different responses (an alert vs. routine noise).

**☕ API Mapping — confirmed directly from Spring Security's own reference docs:** `DefaultAuthenticationEventPublisher` ships with a fixed table mapping specific exception *classes* to specific event *classes* — `BadCredentialsException`, `LockedException`, `DisabledException`, `AccountExpiredException`, `CredentialsExpiredException`, and others, each to its own concrete event type.

**⚠️ The trap, stated in Spring Security's own words:** *"The publisher does an exact Exception match, which means that sub-classes of these exceptions do not also produce events."* A custom exception that `extends LockedException` — exactly the shape a custom lockout mechanism (Topic 2.17) is likely to produce — will **not** trigger an event on its own. Worth remembering before that topic starts.

---

**⚠️ The trap, part 2 — and this one isn't hypothetical, it's sitting in your own project right now:** `ProviderManager` has an internal default field: an `AuthenticationEventPublisher` that does *nothing at all* — a no-op. Spring Boot only wires a *real* one automatically when it builds the entire `AuthenticationManager` for you through its own auto-configuration path. Back in Topic 2.3, you constructed your own `ProviderManager` by hand — `new ProviderManager(List.of(...))` — which bypassed that auto-configuration completely. **Nobody has ever called `.setAuthenticationEventPublisher(...)` on it.** Every login attempt in this project, successful or not, across every topic since 2.3, has published exactly zero events. Verify this against your own running app before reading further.

---

**🌍 Real World:** Even once that's fixed, there's a structural gap worth understanding precisely, not glossing over.

**☕ API Mapping — closing a loop from 2.13/2.14:** `ConcurrentSessionControlAuthenticationStrategy` (2.14) throws `SessionAuthenticationException` from inside `SessionAuthenticationStrategy.onAuthentication()` — called by `AbstractAuthenticationProcessingFilter.successfulAuthentication()`, which only runs **after** `ProviderManager.authenticate()` has already returned successfully and **already published its success event**.

**⚠️ The sharpest trap in this topic:** when a login is blocked purely for having too many active sessions, `ProviderManager` validated the password correctly, declared success, and published `AuthenticationSuccessEvent` — and *only after that* does the session-limit check reject the attempt. A listener watching only for success events would record this as a clean login. A listener watching only for failure events would never see it fail at all. From this event system's point of view, a rejected login due to session limits is invisible on the failure side and misleadingly recorded as a success. Part B proves this exact sequence directly.

**How to observe all of this directly:** a decoupled listener class, added in two stages — first with no publisher wired (proving the silence), then with one wired (proving the fix) — followed by the maxSessions scenario, watched line by line.

| Real-world question | Mechanism |
|---|---|
| Where does auditing get decoupled from the security code itself? | `AuthenticationEventPublisher`, called from inside `ProviderManager` only |
| Why do subclasses of mapped exceptions silently produce nothing? | Exact-class matching, by design — worth remembering for 2.17 |
| Why has this project audited nothing since Topic 2.3? | A hand-built `ProviderManager` defaults to a no-op publisher unless wired explicitly |
| Can a login "succeed" and "fail" at the same time, event-wise? | Yes — a maxSessions rejection fires a real success event, then fails afterward, invisibly to this system |

---

## Part B — Lab

**Modules touched:** `authentication/` (extends 2.3's `AuthenticationManagerConfig` directly)

### API surface covered this topic

| API | Purpose |
|---|---|
| `AuthenticationEventPublisher` (interface) | `publishAuthenticationSuccess()` / `publishAuthenticationFailure()` |
| `DefaultAuthenticationEventPublisher` | Default implementation; exact-match exception-to-event table |
| `ProviderManager.setAuthenticationEventPublisher(...)` | The missing wiring since Topic 2.3 |
| `AuthenticationSuccessEvent` | Fired on success |
| `AbstractAuthenticationFailureEvent` | Base type for all mapped failure events |
| `@EventListener` | Spring's own mechanism — no Spring Security-specific listener interface required |

### `src/main/java/com/labs/formauth/authentication/AuthenticationAuditListener.java`
```java
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
```

### `src/main/java/com/labs/formauth/authentication/AuthenticationManagerConfig.java` (modified — the 2.3 file)
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
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@Configuration
public class AuthenticationManagerConfig {

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService,
                                                                PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    // NOT provided automatically just because spring-security is on the
    // classpath - Boot only wires this for you along the auto-configured
    // AuthenticationManagerBuilder path, which building ProviderManager
    // by hand (below) bypasses entirely. Without this bean, the manager
    // falls back to its internal no-op publisher - silently, with no error.
    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        return new DefaultAuthenticationEventPublisher(applicationEventPublisher);
    }

    @Bean
    public AuthenticationManager authenticationManager(DaoAuthenticationProvider daoAuthenticationProvider,
                                                         BackupCredentialsAuthenticationProvider backupProvider,
                                                         AuthenticationEventPublisher authenticationEventPublisher) {
        ProviderManager manager = new ProviderManager(List.of(daoAuthenticationProvider, backupProvider));
        manager.setEraseCredentialsAfterAuthentication(true);

        // THE FIX - without this single line, every login attempt in this
        // project, since Topic 2.3, has published nothing at all.
        manager.setAuthenticationEventPublisher(authenticationEventPublisher);

        return manager;
    }
}
```

### Step 1 — prove the silence first

Comment out just the one line `manager.setAuthenticationEventPublisher(authenticationEventPublisher);` (leave everything else, including the listener, in place).

```
mvn spring-boot:run
```
```
T=$(curl -s http://localhost:8081/login | grep -oP '(?<=name="_csrf" value=")[^"]*')
curl -c cookies.txt -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123&_csrf=$T" -v
curl -X POST http://localhost:8081/perform_login -d "user=alice&pass=WRONG&_csrf=$T" -v
```
**Expected:** you'll see the usual `[2.2]`, `[2.7]` console lines from earlier topics — but **zero `[2.16]` lines**, for either the success or the failure. The listener exists, is correctly registered, and receives nothing, because nothing was ever published to it.

### Step 2 — wire the fix, repeat identically

Uncomment the line, restart, repeat the exact same two curl commands.

**Expected now:**
```
[2.16] AUDIT SUCCESS - principal=alice, authorities=[ROLE_USER]
[2.16] AUDIT FAILURE - principal=alice, exception=BadCredentialsException, message=Bad credentials
```
Same code paths as Step 1 — the only change was one line, seven topics after it should have mattered.

### Step 3 — the capstone: a "success" that isn't one

Ensure `maximumSessions(1)` / `maxSessionsPreventsLogin(true)` are still active from Topic 2.14. Log in once (session A), then attempt a second login as alice from a fresh cookie jar, without logging out session A first:
```
curl -c session_a.txt -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123&_csrf=$T" -v

T2=$(curl -s http://localhost:8081/login | grep -oP '(?<=name="_csrf" value=")[^"]*')
curl -c session_b.txt -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123&_csrf=$T2" -v
```
**Expected console output for the second attempt:**
```
[2.16] AUDIT SUCCESS - principal=alice, authorities=[ROLE_USER]
```
**and nothing else** — no `[2.16] AUDIT FAILURE` line at all — even though the actual HTTP response is `302 Location: /login?too-many-sessions`, and the browser experience is total failure. `ProviderManager` genuinely succeeded and published exactly what it was supposed to; the rejection happened one layer later, in a component this event system was never wired to hear from.

**Confirm the failure side still works correctly for an ordinary bad password**, run immediately after, for direct contrast:
```
curl -X POST http://localhost:8081/perform_login -d "user=alice&pass=WRONG&_csrf=$T2" -v
```
**Expected:** `[2.16] AUDIT FAILURE - ... BadCredentialsException` — proving the gap is specific to session-strategy rejections, not a general malfunction.

### Try it yourself

1. Trigger a login as `bob` (locked, from Topic 2.4/2.7). Confirm `[2.16] AUDIT FAILURE ... LockedException` fires correctly — `LockedException` is thrown as the exact class, not a custom subclass, so exact-match mapping works here without any extra configuration.
2. Add a print statement inside `BackupCredentialsAuthenticationProvider` (2.3) confirming it still runs exactly when Part A/2.3 said it would. Then log in as `breakglass`/`emergency123` and confirm `[2.16] AUDIT SUCCESS` fires with `principal=breakglass` — proving the event publisher sees success from *either* provider in the chain, not just `DaoAuthenticationProvider`.
3. Add a second `@EventListener` method to a *new*, separate class with no relation to `AuthenticationAuditListener` — confirm both listeners fire independently for the same login attempt. This directly demonstrates the "many independent consumers, none aware of each other" decoupling Part A opened with.

### Delta

**Added:** `authentication/AuthenticationAuditListener.java`
**Modified:** `authentication/AuthenticationManagerConfig.java` (added `AuthenticationEventPublisher` bean, wired into `ProviderManager`)