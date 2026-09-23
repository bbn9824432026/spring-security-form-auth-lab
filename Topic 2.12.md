# Topic 2.12 — Logout mechanics

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** "Logging out" has to mean more than the browser forgetting a cookie. Session-based authentication works because a session ID, once issued, points to real state living in the server's memory (or store) — an `HttpSession` object that says "this ID is currently authenticated as alice." If logout only told the *browser* to discard its copy of that ID, the server-side session object would keep living, keep being valid, for as long as its timeout allows. Anyone else holding that same ID — captured over an unencrypted connection years ago, stolen via an unrelated XSS bug, or simply the next person to use a shared computer if the cookie wasn't actually cleared — could still use it. A real logout has to destroy the server-side state itself, not just the client's pointer to it.

---

**🌍 Real World:** Before touching any of that, something has to recognize "this specific request is a logout request" and route it differently from every other request in the chain — the exact same pattern you've now seen for login (`UsernamePasswordAuthenticationFilter`, 2.2) and for blocked access (`ExceptionTranslationFilter`, 2.9).

**☕ API Mapping:** `LogoutFilter` is that recognizer. But *how* it recognizes a match is where this topic has a genuine surprise waiting — one that's been sitting in your own project since Topic 2.1.

**⚠️ The trap — and this one isn't hypothetical, it's already in your codebase:** `LogoutConfigurer` decides its matcher like this: if a `CsrfConfigurer` is present on the `HttpSecurity` builder **at all** — not "is CSRF actually enforcing," just *present* — the logout matcher becomes `POST /logout` only. Every `SecurityConfig.java` you've written since Topic 2.1 called `.csrf(csrf -> csrf.disable())`. Calling `.disable()` still *applies* the `CsrfConfigurer` to the builder — it doesn't remove it. That means every `<a href="/logout">` link sitting in `home.html` and `profile.html` since Topic 2.1 — through the entire disabled-CSRF period *and* the enabled period since 2.10 — has never once worked as a plain link. Go check this against your own running app before reading any further; Part B does exactly that as its first step.

---

**🌍 Real World:** Once `LogoutFilter` genuinely matches, the actual destruction work isn't done by the filter itself — it's delegated, piece by piece, to an ordered list of narrowly-scoped objects, each responsible for exactly one physical cleanup action.

**☕ API Mapping — the default list, in order:**
1. **`CsrfLogoutHandler`** — deletes the current CSRF token from its repository. Without this, the next anonymous visitor sharing this browser session's remnants could inherit a token tied to alice's now-dead session.
2. **`SecurityContextLogoutHandler`** — the core one. Calls `request.getSession(false)` — **`false`**, deliberately, never `getSession()` — and if a session genuinely exists, calls `.invalidate()` on it, which is the real, server-side destruction Part A opened with. It also clears the in-memory `SecurityContextHolder` for the current thread.
3. **`CookieClearingLogoutHandler`** — sends `Set-Cookie` headers with `Max-Age=0` for named cookies (`JSESSIONID` by default) so the browser drops its copy too — belt-and-suspenders on top of the server-side invalidation, not a substitute for it.

**Deeper mechanism, closing a loop from 2.10:** `request.getSession(false)` — never manufacture a session just to destroy one that was never there. This is the exact same "don't create state you don't need" philosophy you already saw in CSRF's deferred token supplier. Spring Security applies this principle in more than one unrelated place, independently.

---

**🌍 Real World:** After every handler in the list has run, one final object writes the actual HTTP response.

**☕ API Mapping:** `LogoutSuccessHandler` — same one-method, writes-the-response-directly shape you've now built three times (`AuthenticationSuccessHandler` 2.6, `AuthenticationFailureHandler` 2.7, `AuthenticationEntryPoint` 2.9). The default, `SimpleUrlLogoutSuccessHandler`, targets `{loginPage}?logout` — which is exactly why your login page has had a `?logout` query param check sitting unused in earlier topics' comments.

**One clarifying note, since it's easy to overgeneralize from Topic 2.1:** `/login` needed `.permitAll()` because an *unauthenticated* browser must be able to reach it. `/logout` doesn't need that at all — by definition, only an already-authenticated request ever meaningfully hits it, so it can sit comfortably under `anyRequest().authenticated()` without special treatment.

| Real-world question | Mechanism |
|---|---|
| What must actually be destroyed? | The server-side `HttpSession`, not just the browser's cookie copy |
| How does a request get recognized as "this is a logout"? | `LogoutFilter`'s matcher — **POST-only whenever a `CsrfConfigurer` is present at all**, even disabled |
| Who does the real invalidation? | `SecurityContextLogoutHandler` — `getSession(false)`, never manufactures one |
| Who tells the browser to drop its cookie too? | `CookieClearingLogoutHandler` |
| Who prevents token reuse into the next anonymous visit? | `CsrfLogoutHandler` |
| What writes the final response? | `LogoutSuccessHandler` — same interface shape as 2.6/2.7/2.9 |

---

## Part B — Lab

**Modules touched:** `logout/` (new), `web/`, `config/`, `templates/`

### API surface covered this topic

| API | Purpose |
|---|---|
| `LogoutFilter` | Matches logout requests; delegates to the handler list, then the success handler |
| `LogoutHandler` (interface) | One narrow cleanup action per implementation |
| `SecurityContextLogoutHandler` | Real session invalidation + context clearing |
| `CookieClearingLogoutHandler` | Tells the browser to drop named cookies |
| `CsrfLogoutHandler` | Deletes the CSRF token on logout |
| `LogoutSuccessHandler` / `SimpleUrlLogoutSuccessHandler` | Final response construction |
| `HttpSecurity.logout(Customizer<LogoutConfigurer<HttpSecurity>>)` | Entry point; `.logoutUrl()`, `.logoutSuccessHandler()`, `.deleteCookies()`, `.permitAll()` |

### Step 1 — prove the trap, against the app exactly as it stands right now

```
mvn spring-boot:run
```
```
TOKEN=$(curl -s http://localhost:8081/login | grep -oP '(?<=name="_csrf" value=")[^"]*')
curl -c cookies.txt -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123&_csrf=$TOKEN" -v
curl -b cookies.txt http://localhost:8081/logout -v
```
**Expected: `405 Method Not Allowed`.** Every `<a href="/logout">` link since Topic 2.1 has always produced exactly this. Confirm the session is still fully alive:
```
curl -b cookies.txt http://localhost:8081/
```
Still shows `Signed in as: alice` — the failed logout attempt changed nothing.

### `src/main/java/com/labs/formauth/logout/LabLogoutSuccessHandler.java`
```java
package com.labs.formauth.logout;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

// Runs LAST - every default LogoutHandler (SecurityContextLogoutHandler,
// CookieClearingLogoutHandler, CsrfLogoutHandler) has already executed by
// the time this method is called. Same ordering pattern as 2.6's success
// handler running after SecurityContextRepository had already saved.
public class LabLogoutSuccessHandler implements LogoutSuccessHandler {

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                 Authentication authentication) throws IOException {
        String who = (authentication != null) ? authentication.getName() : "unknown";
        System.out.println("[2.12] logout success handler running for: " + who);
        response.sendRedirect("/login?logout");
    }
}
```

### `src/main/java/com/labs/formauth/logout/LogoutConfig.java`
```java
package com.labs.formauth.logout;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
public class LogoutConfig {

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return new LabLogoutSuccessHandler();
    }
}
```

### `src/main/java/com/labs/formauth/web/DebugController.java` (modified — added `showSession`)
```java
package com.labs.formauth.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.stream.Collectors;

@RestController
public class DebugController {

    private final RequestCache requestCache;

    public DebugController(RequestCache requestCache) {
        this.requestCache = requestCache;
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

    @GetMapping("/debug/clear-saved-request")
    public String clearSavedRequest(HttpServletRequest request, HttpServletResponse response) {
        requestCache.removeRequest(request, response);
        return "[2.8] saved request cleared";
    }

    // Added in 2.12 - direct proof of server-side session state, used
    // before and after a logout attempt.
    @GetMapping("/debug/session")
    public String showSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false); // never manufacture one just to check
        if (session == null) {
            return "[2.12] no session exists for this request";
        }
        return "[2.12] session exists - id=" + session.getId();
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
                                            LogoutSuccessHandler logoutSuccessHandler) throws Exception {
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
            // Explicit now - was entirely implicit (and, as Step 1 proved,
            // never actually reachable via a plain <a> link) since Topic 2.1.
            // No .permitAll() needed here - unlike /login, /logout is only
            // ever meaningfully hit by someone already authenticated.
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessHandler(logoutSuccessHandler)
                .deleteCookies("JSESSIONID")
            );

        return http.build();
    }
}
```

### `src/main/resources/templates/home.html` (modified — logout link replaced)
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org"
      xmlns:sec="http://www.thymeleaf.org/extras/spring-security">
<head><title>Form Auth Lab</title></head>
<body>
    <h1>You are logged in.</h1>

    <p>Signed in as: <span sec:authentication="name">?</span></p>
    <p>Authorities: <span sec:authentication="principal.authorities">?</span></p>

    <p><a href="/profile">Go to profile</a></p>

    <!--
      A plain <a href="/logout"> NEVER worked - see Topic 2.12's Part A.
      This must be a POST, and th:action is what gets it a valid CSRF
      token automatically (Topic 2.11's mechanism, reused here).
    -->
    <form th:action="@{/logout}" method="post">
        <button type="submit">Logout</button>
    </form>

    <p sec:authorize="hasRole('ADMIN')">
        <a href="/admin">Go to admin panel</a>
    </p>
    <p sec:authorize-url="/admin">
        (sec:authorize-url agrees: you can reach /admin)
    </p>
</body>
</html>
```

### `src/main/resources/templates/profile.html` (modified — same fix)
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Profile</title></head>
<body>
    <h1>Profile page</h1>
    <p>Logged in as: <span th:text="${username}">?</span></p>
    <p><a href="/">Home</a></p>

    <form th:action="@{/logout}" method="post">
        <button type="submit">Logout</button>
    </form>
</body>
</html>
```

### Run it — the correct flow, end to end

Restart, log in fresh as alice, then hit `/` to render the fixed template and extract the *now-present* logout form's real token:
```
curl -c cookies.txt -X POST http://localhost:8081/perform_login \
  -d "user=alice&pass=password123&_csrf=$(curl -s http://localhost:8081/login | grep -oP '(?<=name=\"_csrf\" value=\")[^\"]*')" -v

curl -b cookies.txt http://localhost:8081/debug/session
# Expected: [2.12] session exists - id=...

LOGOUT_TOKEN=$(curl -s -b cookies.txt http://localhost:8081/ | grep -oP '(?<=name="_csrf" value=")[^"]*')
curl -b cookies.txt -c cookies.txt -X POST http://localhost:8081/logout -d "_csrf=$LOGOUT_TOKEN" -v
```
Console:
```
[2.12] logout success handler running for: alice
```
Response: `302 Location: /login?logout`, and (check with `-v`) a `Set-Cookie: JSESSIONID=; Max-Age=0` line — `CookieClearingLogoutHandler`'s output, on the wire, not asserted.

**Confirm the session is genuinely dead server-side, not just that the cookie was told to clear client-side:**
```
curl -b cookies.txt http://localhost:8081/debug/session
```
**Expected:** `[2.12] no session exists for this request` — even reusing the exact same cookie jar. And:
```
curl -b cookies.txt http://localhost:8081/profile
```
**Expected:** back to a `302` redirect to `/login` — fully logged out, proven two different ways.

### Contrast experiment — comment out `.deleteCookies("JSESSIONID")`

```java
.logout(logout -> logout
    .logoutUrl("/logout")
    .logoutSuccessHandler(logoutSuccessHandler)
    // .deleteCookies("JSESSIONID")
)
```
Restart, repeat the full login → logout sequence, and check the `Set-Cookie` header on the logout response with `-v`. **You'll likely still see it** — `CookieClearingLogoutHandler` with its default no-arg-equivalent construction already targets `JSESSIONID` on its own, since that's the servlet container's default session cookie name. Removing your explicit call doesn't break anything *here* — but it does mean if your app ever uses a different session cookie name, or adds a second cookie (a "remember me" cookie is exactly this shape — Topic 2.15 will need it), nothing clears it unless you name it explicitly. Restore the line once you've confirmed this.

### Try it yourself

1. Repeat Step 1's exact 405 reproduction one more time, but this time also try `curl -b cookies.txt -X PUT http://localhost:8081/logout -v` and `-X DELETE` — confirm both also fail with `405`, proving the matcher really is `POST`-only-and-nothing-else once a `CsrfConfigurer` is present, not "anything except GET."
2. Temporarily remove `.csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository))` entirely from `SecurityConfig` (comment it out) *and* comment out `LogoutConfig`'s effect isn't relevant here — just the csrf line. Restart and try `curl -b cookies.txt http://localhost:8081/logout` as a plain **GET**, with no token at all. Does it now succeed? This directly tests the GitHub-sourced claim from Part A: the matcher depends on `CsrfConfigurer` being *present* on the builder at all, not on CSRF actually being enforced.
3. Log in, then open two separate terminal "sessions" (two separate `cookies.txt` files from two separate logins as alice). Log out using only one of them. Confirm the *other* cookie jar's session is still completely valid via `/debug/session` — logout only ever touches the one session tied to the request that triggered it, never "all of alice's sessions everywhere" (a different, more advanced concept — session management across multiple devices is 2.14's subject).

### Delta

**Added:** `logout/LabLogoutSuccessHandler.java`, `logout/LogoutConfig.java`
**Modified:** `web/DebugController.java` (added `/debug/session`), `config/SecurityConfig.java` (explicit `.logout(...)`), `templates/home.html` and `templates/profile.html` (`<a href="/logout">` replaced with a proper `th:action` form)