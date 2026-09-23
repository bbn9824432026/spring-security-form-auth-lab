# Topic 2.7 — `AuthenticationFailureHandler` & exception-type mapping

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** Same physical situation as 2.6, mirrored — `authenticate()` threw instead of returning, and something still has to write bytes back over that same open connection. But a *failure* carries more information than a success does: it's not just "no," it's "no, and here specifically is why," expressed as a real Java exception type, not a string.

**☕ API Mapping:** `AuthenticationFailureHandler` — one method, `onAuthenticationFailure(request, response, AuthenticationException exception)`. `.failureUrl("/login?error")` from Topic 2.1 built a `SimpleUrlAuthenticationFailureHandler` for you — it redirects to that fixed URL regardless of exception type, but it does one thing worth knowing: it calls `saveException(request, exception)`, which stashes the real exception object into the session under `WebAttributes.AUTHENTICATION_EXCEPTION`. That attribute has been sitting there, retrievable, since Topic 2.1 — you just never read it.

---

**🌍 Real World:** Different failure reasons are physically distinguishable — the JVM already knows the concrete class of the thrown object. The question is only whether your handler chooses to branch on it.

**☕ API Mapping:** the exception hierarchy: `AuthenticationException` is the abstract root. `BadCredentialsException` extends it directly. `LockedException`, `DisabledException`, `AccountExpiredException`, and `CredentialsExpiredException` all extend a shared abstract class, `AccountStatusException` — the exact class you saw named in Topic 2.3's `ProviderManager` loop as one of the two types that get rethrown **immediately**, with no other provider getting a turn.

**Deeper mechanism, tying two topics together:** because these four are `AccountStatusException` subclasses, a locked account short-circuits the entire provider chain from 2.3 — `BackupCredentialsAuthenticationProvider` never even runs for a locked user, regardless of list order. Part B proves this directly against your own 2.3 setup.

---

**⚠️ The trap — and it directly contradicts what feels like the "obviously correct" move:** it's tempting to build a failure handler that shows a distinct message per exception type — "invalid credentials" vs. "account locked" vs. "account disabled" — it feels more honest and more helpful. But recall 2.3's check order: `LockedException`, `DisabledException`, and `AccountExpiredException` all fire from the **pre**-authentication check, which runs *before the password is even compared*. That means submitting a completely wrong password for a locked username still throws `LockedException`, not `BadCredentialsException`. If your failure handler shows a distinct message for that, you've just told anyone — with zero knowledge of the real password — that this specific username exists and is locked. This is the exact same class of leak `hideUserNotFoundExceptions` (2.4) was built to prevent for unknown usernames, quietly reopened through a different exception type.

`CredentialsExpiredException` is the one genuine exception. It only fires from the **post**-authentication check — meaning the correct password was already supplied. Telling that person "your password expired" leaks nothing; they just proved they know the current one.

**How to observe this directly:** log the real exception class internally on every failure, but drive the *external* redirect off a much coarser rule — that split is exactly what Part B's handler does, and the contrast experiment builds the leaky version specifically to make the difference undeniable.

| Exception | Thrown from | Safe to reveal externally? |
|---|---|---|
| `BadCredentialsException` | password comparison (or masked `UsernameNotFoundException`) | Generic message only |
| `LockedException` / `DisabledException` / `AccountExpiredException` | **pre**-check — fires even with a wrong password | No — reveals account existence + state |
| `CredentialsExpiredException` | **post**-check — only after correct password | Yes — nothing new is disclosed |

---

## Part B — Lab

**Modules touched:** `authentication/`, `credentials/`, `config/`, `templates/`

### API surface covered this topic

| API | Purpose |
|---|---|
| `AuthenticationFailureHandler` (interface) | The one method every failure strategy implements |
| `SimpleUrlAuthenticationFailureHandler` | What `.failureUrl()` built in 2.1; stores the exception in session via `saveException()` |
| `WebAttributes.AUTHENTICATION_EXCEPTION` | Session key where the raw exception is stashed |
| `AuthenticationException` / `BadCredentialsException` | Base type / generic credential mismatch |
| `AccountStatusException` (abstract) | Shared superclass — also the type `ProviderManager` (2.3) treats as fatal |
| `LockedException`, `DisabledException`, `AccountExpiredException`, `CredentialsExpiredException` | Concrete account-status failures |
| `FormLoginConfigurer.failureHandler(AuthenticationFailureHandler)` | Wires a custom handler, replacing `.failureUrl()` |

### `src/main/java/com/labs/formauth/credentials/LabUserDetailsService.java` (modified)
```java
package com.labs.formauth.credentials;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class LabUserDetailsService {

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails alice = User.withUsername("alice")
                .password(passwordEncoder.encode("password123"))
                .roles("USER")
                .build();

        UserDetails bob = User.withUsername("bob")
                .password(passwordEncoder.encode("password123"))
                .roles("USER")
                .accountLocked(true)
                .build();

        // Added in 2.7: correct password, expired credentials - the ONE
        // status exception that only ever fires AFTER a correct password.
        UserDetails carol = User.withUsername("carol")
                .password(passwordEncoder.encode("password123"))
                .roles("USER")
                .credentialsExpired(true)
                .build();

        return new InMemoryUserDetailsManager(alice, bob, carol);
    }
}
```

### `src/main/java/com/labs/formauth/authentication/LabAuthenticationFailureHandler.java`
```java
package com.labs.formauth.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

// Production-safe pattern: log the REAL exception type internally, but
// collapse everything except CredentialsExpiredException into one generic
// external message. See Part A for exactly why.
public class LabAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationException exception) throws IOException {

        // Internal audit trail only - nobody outside the server sees this line.
        // Real event-based auditing (not just a print) is Topic 2.16.
        System.out.println("[2.7] internal audit -> " + exception.getClass().getSimpleName()
                + " : " + exception.getMessage());

        if (exception instanceof CredentialsExpiredException) {
            // Safe to reveal: this ONLY fires post-password-check (2.3).
            redirectStrategy.sendRedirect(request, response, "/login?expired");
            return;
        }

        if (exception instanceof LockedException
                || exception instanceof DisabledException
                || exception instanceof AccountExpiredException) {
            // NOT safe to reveal distinctly - these are pre-checks (2.3) and
            // fire even with a wrong password. Same external outcome as
            // plain bad credentials, on purpose.
            redirectStrategy.sendRedirect(request, response, "/login?error");
            return;
        }

        // BadCredentialsException, including the masked "unknown user" case
        // from Topic 2.4's hideUserNotFoundExceptions.
        redirectStrategy.sendRedirect(request, response, "/login?error");
    }
}
```

### `src/main/java/com/labs/formauth/authentication/LeakyAuthenticationFailureHandler.java`
```java
package com.labs.formauth.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

// DELIBERATE CONTRAST — DO NOT USE IN PRODUCTION.
// Reveals account state to anyone who submits ANY password for a known
// username. Exists only to make Part A's trap undeniable.
public class LeakyAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationException exception) throws IOException {
        if (exception instanceof LockedException) {
            redirectStrategy.sendRedirect(request, response, "/login?reason=locked");
            return;
        }
        if (exception instanceof DisabledException) {
            redirectStrategy.sendRedirect(request, response, "/login?reason=disabled");
            return;
        }
        redirectStrategy.sendRedirect(request, response, "/login?reason=bad_credentials");
    }
}
```

### `src/main/java/com/labs/formauth/authentication/FailureHandlerConfig.java`
```java
package com.labs.formauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

@Configuration
public class FailureHandlerConfig {

    @Bean
    public AuthenticationFailureHandler failureHandler() {
        return new LabAuthenticationFailureHandler();

        // TOGGLE for the contrast experiment below:
        // return new LeakyAuthenticationFailureHandler();
    }
}
```

### `src/main/java/com/labs/formauth/config/SecurityConfig.java` (modified)
```java
package com.labs.formauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                            AuthenticationManager authenticationManager,
                                            AuthenticationSuccessHandler successHandler,
                                            AuthenticationFailureHandler failureHandler) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .authenticationManager(authenticationManager)
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/perform_login")
                .usernameParameter("user")
                .passwordParameter("pass")
                .successHandler(successHandler)
                .failureHandler(failureHandler)   // replaces .failureUrl() from 2.1
                .permitAll()
            )
            .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
```

### `src/main/resources/templates/login.html` (modified)
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Login</title></head>
<body>
<h1>Log in</h1>

<p th:if="${param.error}" style="color:red;">Invalid username or password.</p>
<p th:if="${param.expired}" style="color:orange;">Your password has expired. Please reset it.</p>
<!-- only appears while LeakyAuthenticationFailureHandler is active -->
<p th:if="${param.reason}" style="color:red;">Failure reason (leaked): <span th:text="${param.reason}">?</span></p>

<form action="/perform_login" method="post">
    <label>Username: <input type="text" name="user"/></label><br/>
    <label>Password: <input type="password" name="pass"/></label><br/>
    <button type="submit">Log in</button>
</form>
</body>
</html>
```

### Run it

```
mvn spring-boot:run
```

**Case 1 — correctly identified, safely revealed (carol, correct password, expired creds):**
```
curl -X POST http://localhost:8081/perform_login -d "user=carol&pass=password123" -v
```
Console: `[2.7] internal audit -> CredentialsExpiredException : ...`
Response: `302 Location: /login?expired` → orange message renders.

**Case 2 — the trap, proven (bob, locked, WRONG password on purpose):**
```
curl -X POST http://localhost:8081/perform_login -d "user=bob&pass=totallywrong" -v
```
Console: `[2.7] internal audit -> LockedException : ...` — not `BadCredentialsException`, even though the password was wrong. This is Part A's pre-check-before-password-check claim, proven with your own request.
Response: `302 Location: /login?error` — **identical** external URL to a plain wrong-password attempt. Confirm by running the same command against `alice` with a wrong password — same `/login?error`, same generic red message, indistinguishable from outside.

### Contrast experiment — reproduce the leak directly

Toggle `FailureHandlerConfig` to `LeakyAuthenticationFailureHandler`, restart, repeat Case 2:
```
curl -X POST http://localhost:8081/perform_login -d "user=bob&pass=totallywrong" -v
```
**Expected:** `302 Location: /login?reason=locked` — the browser now literally displays "Failure reason (leaked): locked," having learned bob's account exists and is locked from a completely wrong password. Revert the toggle once you've confirmed this.

### Try it yourself

1. Reproduce Case 2 exactly as written, then check the console timing — confirm `LockedException` fires with **no measurable delay difference** compared to a correct-password attempt, since the pre-check happens before the (comparatively slow) BCrypt comparison from Topic 2.5 even runs.
2. Wire the `AuthenticationManagerConfig`/`BackupCredentialsAuthenticationProvider` chain from Topic 2.3 back in, then log in as `bob` (locked) with any password. Check the console — does `[2.3] BackupProvider` ever print? This confirms `LockedException`, as an `AccountStatusException`, short-circuits `ProviderManager`'s loop exactly as 2.3 described, with no other provider getting a turn.
3. Attempt login as `carol` with a **wrong** password (not the correct one). Which redirect do you land on — `/login?expired` or `/login?error`? This confirms `CredentialsExpiredException` truly only fires from the post-check, and a wrong password short-circuits before that check is ever reached, regardless of the account's expired status.

### Delta

**Added:** `authentication/LabAuthenticationFailureHandler.java`, `authentication/LeakyAuthenticationFailureHandler.java`, `authentication/FailureHandlerConfig.java`
**Modified:** `config/SecurityConfig.java` (`.failureUrl()` → `.failureHandler(...)`), `credentials/LabUserDetailsService.java` (added `carol`), `templates/login.html`