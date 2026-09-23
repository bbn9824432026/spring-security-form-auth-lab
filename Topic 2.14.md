# Topic 2.14 — Concurrent session control

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** Nothing built so far stops alice from being simultaneously logged in on her laptop, her phone, and a library computer — each is a completely separate `HttpSession` object, unaware the others exist. For a lot of real requirements — "only one active device," or automatically killing an old session the instant a new login happens as a defense against a stolen-but-still-live session — the application needs a single, shared, cross-request piece of bookkeeping: *right now, across the whole running app, which session IDs belong to which principal?* HTTP itself gives you nothing like this; each request is independent by design.

**☕ API Mapping:** `SessionRegistry` — a genuinely shared, in-memory structure (the default `SessionRegistryImpl` is backed by plain concurrent maps), holding `principal -> List<SessionInformation>`. Everything in this topic is either writing to it or reading from it.

---

**🌍 Real World:** Recall Topic 2.13's stack trace: `CompositeSessionAuthenticationStrategy` delegating to a *list* of strategies. That composite isn't just holding one strategy — once you configure `maximumSessions(...)`, it's holding **three**, run in a fixed, deliberate order, on every successful login: `ConcurrentSessionControlAuthenticationStrategy` first, `ChangeSessionIdAuthenticationStrategy` (2.13) second, `RegisterSessionAuthenticationStrategy` last.

**Deeper mechanism — why that exact order matters:** the *limit check* has to run **before** the ID changes, against the currently-registered sessions, using the old identity context. Registration has to run **last**, so what actually gets written into the registry is the *final*, post-fixation-protection session ID — not one that's about to be replaced. This is the same architectural pattern you've now seen three separate times in this course: a list of narrow, single-purpose objects run in a fixed sequence (`ProviderManager`'s providers in 2.3, `LogoutFilter`'s handlers in 2.12, and now this).

---

**🌍 Real World:** When the limit is actually exceeded, there are two entirely different things that could physically happen, and Spring Security supports both as opposite configuration choices:

**☕ API Mapping:** `.maxSessionsPreventsLogin(true)` — the **new** login attempt itself is rejected. `ConcurrentSessionControlAuthenticationStrategy` throws `SessionAuthenticationException` right there, during the session-strategy step — which runs strictly *after* the password already checked out correctly (the exact same "post-check, safe to reveal" category as `CredentialsExpiredException` from Topic 2.7's safety table — this genuinely belongs in that same row, for the same reason). `.maxSessionsPreventsLogin(false)` (the default) — the new login *succeeds*, and instead the *oldest* existing session(s) get flagged: `SessionInformation.expireNow()` sets a boolean on the registry entry.

**⚠️ The trap, part 1 — and it's not what "expire" sounds like:** flagging a `SessionInformation` as expired does **not** immediately kill that old session. The old browser tab keeps working, completely normally, for any request it happens to make in the meantime. The kill only happens on that old session's **next** incoming request, when a separate filter, `ConcurrentSessionFilter`, checks the registry, sees the flag, invalidates the real `HttpSession` right then, and redirects using `.expiredUrl(...)`. "Kicked out instantly" is a common but inaccurate mental model — it's "kicked out on next contact."

---

**⚠️ The trap, part 2 — the single most common real-world bug with this feature, and it has nothing to do with the DSL you write:** the registry has to be told when a session dies from a plain **timeout**, not just an explicit logout. Timeouts are a servlet-container event, not a Spring Security one — `SessionRegistry` never hears about them unless something bridges that gap. That bridge is `HttpSessionEventPublisher`, a `ServletContextListener` you must register as a bean yourself. Without it, the registry keeps counting long-dead, timed-out sessions as active forever — meaning `maximumSessions(1)` can permanently lock a legitimate user out, convinced a session is still open when the browser that held it closed hours ago.

**How to observe all of this directly:** Part B builds a debug endpoint reading the real `SessionRegistry` state — session IDs, their expired flags, last-request timestamps — and deliberately shortens the session timeout so the staleness bug is observable in seconds instead of the usual 30 minutes.

| Real-world question | Mechanism |
|---|---|
| Shared bookkeeping across all sessions app-wide | `SessionRegistry` / `SessionRegistryImpl` |
| Who checks the limit, and against what | `ConcurrentSessionControlAuthenticationStrategy` — runs first, before the ID changes |
| Two different outcomes on exceeding the limit | `maxSessionsPreventsLogin(true)` blocks new login vs. `false` flags old ones |
| When does a flagged old session actually die? | Not immediately — only on its *next* request, via `ConcurrentSessionFilter` |
| Why can the registry go stale over time? | Timeouts never reach it without `HttpSessionEventPublisher` bridging the servlet event |

---

## Part B — Lab

**Modules touched:** `authentication/`, `web/`, `config/`, `templates/`

### API surface covered this topic

| API | Purpose |
|---|---|
| `SessionRegistry` / `SessionRegistryImpl` | The shared registry itself |
| `SessionInformation` | One entry — session ID, principal, last-request time, expired flag |
| `HttpSecurity.sessionManagement().maximumSessions(int)` | Enables concurrent session control |
| `.maxSessionsPreventsLogin(boolean)` | Chooses which of the two outcomes applies |
| `.expiredUrl(String)` | Where `ConcurrentSessionFilter` redirects a session it just discovered was flagged |
| `.sessionRegistry(SessionRegistry)` | Wires an explicit registry bean |
| `HttpSessionEventPublisher` | Bridges real servlet timeout events into the registry |
| `SessionAuthenticationException` | Thrown by the strategy when a new login is blocked outright |

### `src/main/java/com/labs/formauth/authentication/SessionRegistryConfig.java`
```java
package com.labs.formauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;

@Configuration
public class SessionRegistryConfig {

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    // THE FIX for registry staleness on timeout (Part A, trap #2).
    // Deliberately commented out for Step 1's broken demonstration below.
    // @Bean
    // public org.springframework.security.web.session.HttpSessionEventPublisher httpSessionEventPublisher() {
    //     return new org.springframework.security.web.session.HttpSessionEventPublisher();
    // }
}
```

### `src/main/java/com/labs/formauth/authentication/LabAuthenticationFailureHandler.java` (modified — one new branch)
```java
package com.labs.formauth.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.SessionAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

public class LabAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationException exception) throws IOException {

        System.out.println("[2.7] internal audit -> " + exception.getClass().getSimpleName()
                + " : " + exception.getMessage());

        if (exception instanceof CredentialsExpiredException) {
            redirectStrategy.sendRedirect(request, response, "/login?expired");
            return;
        }

        // Added in 2.14: this ONLY fires after the password already checked
        // out (Topic 2.13's ConcurrentSessionControlAuthenticationStrategy
        // runs post-success) - the exact same safe-to-reveal category as
        // CredentialsExpiredException above, for the exact same reason.
        if (exception instanceof SessionAuthenticationException) {
            redirectStrategy.sendRedirect(request, response, "/login?too-many-sessions");
            return;
        }

        if (exception instanceof LockedException
                || exception instanceof DisabledException
                || exception instanceof AccountExpiredException) {
            redirectStrategy.sendRedirect(request, response, "/login?error");
            return;
        }

        redirectStrategy.sendRedirect(request, response, "/login?error");
    }
}
```

### `src/main/java/com/labs/formauth/web/DebugController.java` (modified — added session-registry inspection)
```java
package com.labs.formauth.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
public class DebugController {

    private final RequestCache requestCache;
    private final SessionRegistry sessionRegistry;

    public DebugController(RequestCache requestCache, SessionRegistry sessionRegistry) {
        this.requestCache = requestCache;
        this.sessionRegistry = sessionRegistry;
    }

    @GetMapping("/debug/saved-request")
    public String showSavedRequest(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest saved = requestCache.getRequest(request, response);
        if (saved == null) {
            return "[2.8] no saved request in this session";
        }
        String params = saved.getParameterMap().entrySet().stream()
                .map(e -> e.getKey() + "=" + String.join(",", e.getValue()))
                .collect(Collectors.joining("; "));
        return "[2.8] method=" + saved.getMethod()
                + " | redirectUrl=" + saved.getRedirectUrl()
                + " | parameters={" + params + "}";
    }

    @GetMapping("/debug/session")
    public String showSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return "[2.12] no session exists for this request";
        }
        return "[2.12] session exists - id=" + session.getId();
    }

    // Added in 2.14 - direct proof of what the registry actually believes
    // is currently active for a given username, including stale entries.
    @GetMapping("/debug/sessions/{username}")
    public String showSessionsForUser(@PathVariable String username) {
        for (Object principal : sessionRegistry.getAllPrincipals()) {
            String principalName = (principal instanceof UserDetails ud) ? ud.getUsername() : principal.toString();
            if (principalName.equals(username)) {
                List<SessionInformation> sessions = sessionRegistry.getAllSessions(principal, true);
                if (sessions.isEmpty()) {
                    return "[2.14] registry has principal '" + username + "' but no session entries";
                }
                return sessions.stream()
                        .map(si -> "sessionId=" + si.getSessionId()
                                + ", expired=" + si.isExpired()
                                + ", lastRequest=" + si.getLastRequest())
                        .collect(Collectors.joining("\n"));
            }
        }
        return "[2.14] no registry entries found for " + username;
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
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.RequestCache;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                            AuthenticationManager authenticationManager,
                                            AuthenticationSuccessHandler successHandler,
                                            AuthenticationFailureHandler failureHandler,
                                            RequestCache requestCache,
                                            AuthenticationEntryPoint authenticationEntryPoint,
                                            AccessDeniedHandler accessDeniedHandler,
                                            CsrfTokenRepository csrfTokenRepository,
                                            LogoutSuccessHandler logoutSuccessHandler,
                                            SessionRegistry sessionRegistry) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/debug/**", "/403").permitAll()
                .requestMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .authenticationManager(authenticationManager)
            .requestCache(cache -> cache.requestCache(requestCache))
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
            )
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/perform_login")
                .usernameParameter("user")
                .passwordParameter("pass")
                .successHandler(successHandler)
                .failureHandler(failureHandler)
                .permitAll()
            )
            .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository))
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessHandler(logoutSuccessHandler)
                .deleteCookies("JSESSIONID")
            )
            .sessionManagement(session -> {
                session.sessionFixation(fixation -> fixation.changeSessionId());
                // Composite order internally: limit check -> ID change ->
                // registration - see Part A. maxSessionsPreventsLogin(true)
                // means a blocked login throws SessionAuthenticationException,
                // routed to our failureHandler's new branch above.
                session.maximumSessions(1)
                        .maxSessionsPreventsLogin(true)
                        .expiredUrl("/login?expired-session")
                        .sessionRegistry(sessionRegistry);
            });

        return http.build();
    }
}
```

### `src/main/resources/application.yml` (modified — LAB ONLY)
```yaml
server:
  port: 8081
  # LAB ONLY - absurdly short so registry staleness is observable in
  # seconds instead of the usual 30 minutes. Never do this in production.
  servlet:
    session:
      timeout: 8s

logging:
  level:
    org.springframework.security: DEBUG
```

### `src/main/resources/templates/login.html` (modified — one new message line)
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Login</title></head>
<body>
<h1>Log in</h1>

<p th:if="${param.error}" style="color:red;">Invalid username or password.</p>
<p th:if="${param.expired}" style="color:orange;">Your password has expired. Please reset it.</p>
<p th:if="${param['expired-session']}" style="color:orange;">Your session expired because you logged in elsewhere.</p>
<p th:if="${param['too-many-sessions']}" style="color:red;">You're already logged in elsewhere. Log out there first.</p>

<form th:action="@{/perform_login}" method="post">
    <label>Username: <input type="text" name="user"/></label><br/>
    <label>Password: <input type="password" name="pass"/></label><br/>
    <button type="submit">Log in</button>
</form>
</body>
</html>
```

### Run it — the block-new-login behavior

```
mvn spring-boot:run
```
```
curl -c session_a.txt http://localhost:8081/login -o login_page.html
T1=$(grep -oP '(?<=name="_csrf" value=")[^"]*' login_page.html)
curl -b session_a.txt -c session_a.txt -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123&_csrf=$T1" -v
```
Check the registry:
```
curl http://localhost:8081/debug/sessions/alice
```
**Expected:** one entry, `expired=false`.

Now a *second* "device" tries to log in as alice, before the first ever logs out:
```
curl -c session_b.txt http://localhost:8081/login -o login_page2.html
T2=$(grep -oP '(?<=name="_csrf" value=")[^"]*' login_page2.html)
curl -b session_b.txt -c session_b.txt -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123&_csrf=$T2" -v
```
**Expected: `302 Location: /login?too-many-sessions`.** Console shows `[2.7] internal audit -> SessionAuthenticationException : Maximum sessions of 1 for this principal exceeded`. Session A is completely untouched — confirm with `curl -b session_a.txt http://localhost:8081/profile` (still `200`).

### Contrast experiment — the registry staleness bug, reproduced exactly

With the `HttpSessionEventPublisher` bean still commented out, log in as alice (session A, as above), then **wait 10 seconds** (longer than the 8s timeout) without touching session A at all:
```
sleep 10
curl -c session_c.txt http://localhost:8081/login -o login_page3.html
T3=$(grep -oP '(?<=name="_csrf" value=")[^"]*' login_page3.html)
curl -b session_c.txt -c session_c.txt -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123&_csrf=$T3" -v
```
**Expected: still blocked with `?too-many-sessions`**, even though session A's underlying `HttpSession` has genuinely already timed out server-side. Confirm the registry's confusion directly:
```
curl http://localhost:8081/debug/sessions/alice
```
It still lists the old, dead session as if it were live — the registry was never told.

**Now uncomment the `HttpSessionEventPublisher` bean**, restart, and repeat the exact same sequence:
```
curl -c session_a.txt http://localhost:8081/login -o login_page.html
T1=$(grep -oP '(?<=name="_csrf" value=")[^"]*' login_page.html)
curl -b session_a.txt -c session_a.txt -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123&_csrf=$T1" -v
sleep 10
curl -c session_c.txt http://localhost:8081/login -o login_page3.html
T3=$(grep -oP '(?<=name="_csrf" value=")[^"]*' login_page3.html)
curl -b session_c.txt -c session_c.txt -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123&_csrf=$T3" -v
```
**Expected this time: `302 Location: /`** — login succeeds. The listener bridged the real timeout event, the registry correctly dropped the dead entry, and the slot was genuinely free.

### Try it yourself

1. Switch `.maxSessionsPreventsLogin(true)` to `false`, restart, and log in as alice from two "devices" back to back. Confirm the *second* login succeeds outright — then hit `curl -b session_a.txt http://localhost:8081/profile` (the *first* session). Is it killed on this very request? Check the response — this proves Part A's "not immediately, only on next contact" claim directly.
2. Right after reproducing #1, check `/debug/sessions/alice` before *and* after that follow-up request on session A — watch the `expired` flag flip from `true` to the entry disappearing entirely once `ConcurrentSessionFilter` actually processes it.
3. Set `maximumSessions(2)` instead of `1`, and log in as alice from three separate "devices" in sequence. With `maxSessionsPreventsLogin(false)`, which session gets flagged as expired — the oldest, or the newest? Confirm by checking `/debug/sessions/alice` after each login.

### Delta

**Added:** `authentication/SessionRegistryConfig.java`
**Modified:** `authentication/LabAuthenticationFailureHandler.java` (new `SessionAuthenticationException` branch), `web/DebugController.java` (added `/debug/sessions/{username}`), `config/SecurityConfig.java` (`.sessionManagement(...)` extended), `application.yml` (lab-only short session timeout), `templates/login.html` (two new message lines)