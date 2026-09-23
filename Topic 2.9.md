# Topic 2.9 — `AuthenticationEntryPoint` for form login

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** Somewhere deep in the filter chain — past every filter you've built so far — a decision gets made about whether this request is even allowed to proceed. When that decision says "no," it does so by *throwing a Java exception*. But an exception thrown inside a filter chain doesn't know how to become an HTTP response on its own — left alone, it would just propagate up and the servlet container would show a generic, ugly error page. Something has to sit at exactly the right point in the chain, catch that exception, and translate it into a deliberate response.

**☕ API Mapping:** That's `ExceptionTranslationFilter`, positioned specifically to wrap everything after it — including the authorization check itself. It's the reason you've never seen a raw stack trace from a blocked request; it's been quietly converting exceptions into responses since the very first topic in this group.

**Deeper mechanism — why there's always *something* to check:** even a completely unauthenticated request doesn't have a `null` `Authentication` sitting in the context. `AnonymousAuthenticationFilter` runs earlier and installs a placeholder `AnonymousAuthenticationToken` for anyone who hasn't logged in. This matters in a moment.

---

**🌍 Real World:** Not every denial is the same *kind* of denial. "I don't know who you are" and "I know exactly who you are, and you're still not allowed" are physically different situations, and they demand different responses — one should offer a way to fix the problem (log in), the other genuinely shouldn't.

**☕ API Mapping:** `ExceptionTranslationFilter` branches on exception type:
- `AuthenticationException` → always goes to `AuthenticationEntryPoint`.
- `AccessDeniedException` → checked against the current `Authentication`. If it's that placeholder `AnonymousAuthenticationToken` from a moment ago, the filter treats it as "not really logged in" and routes it to the **same** `AuthenticationEntryPoint` anyway — because asking an anonymous visitor to log in makes sense. Only when the principal is a genuinely authenticated, non-anonymous user does `AccessDeniedException` go to a completely different object: `AccessDeniedHandler`.

**⚠️ The trap:** this is easy to get backwards. A logged-in user with insufficient permissions does **not** get redirected to `/login` — form login has nothing to do with that path at all. They get whatever `AccessDeniedHandler` decides, which by default is a plain `403` — Boot's whitelabel error page, not your login form. People frequently assume `.loginPage(...)` "handles all access problems" because it's the only security-related config they've touched; it handles exactly one category of problem.

---

**🌍 Real World:** Once `ExceptionTranslationFilter` decides "this genuinely needs authentication," it does two things before handing off: wipes any placeholder context (`SecurityContextHolder.clearContext()` — the exact object from your other project's 1.3 topic), and saves the request (`RequestCache.saveRequest(...)` — 2.8's mechanism, and now you know precisely *who* calls it and *when*: right here, before the challenge is even issued).

**☕ API Mapping:** Only then does it call `authenticationEntryPoint.commence(request, response, authException)` — one method, no return value, writes the response itself. `.loginPage("/login")` from Topic 2.1 built exactly one implementation of this: `LoginUrlAuthenticationEntryPoint`. Its `commence()` resolves the target URL (handling relative vs. absolute, an `forceHttps` flag) and hands off to a `RedirectStrategy` — the **same interface** `LabAuthenticationSuccessHandler` used in 2.6 to issue its own redirect. Two entirely different topics, same tiny abstraction underneath.

**Deeper mechanism, closing a loop from 2.1:** if you explicitly configure an `AuthenticationEntryPoint` yourself (this topic's lab does exactly that), it takes priority — `.formLogin().loginPage(...)` only builds its own default entry point when none has been explicitly set. Explicit configuration always wins over the implicit one you've been relying on since 2.1.

**How to observe this directly:** print at the exact moment `commence()` is called, and separately at the exact moment `AccessDeniedHandler.handle()` is called — Part B does both, against a real authenticated-but-forbidden request, so you see with your own eyes which object actually runs.

| Real-world question | Mechanism |
|---|---|
| Who catches exceptions from deep in the chain? | `ExceptionTranslationFilter` |
| "No identity at all" vs. "identity, but not enough" | `AuthenticationEntryPoint` vs. `AccessDeniedHandler` — genuinely different objects |
| Anonymous user denied access — which path? | Still `AuthenticationEntryPoint` — anonymous is treated as "ask them to log in" |
| What does `.loginPage()` actually build? | `LoginUrlAuthenticationEntryPoint`, unless you explicitly configure your own |
| What physically writes the challenge redirect? | `RedirectStrategy` — the same interface from 2.6's success handler |

---

## Part B — Lab

**Modules touched:** `authentication/`, `web/`, `config/`, `templates/`

### API surface covered this topic

| API | Purpose |
|---|---|
| `AuthenticationEntryPoint.commence(request, response, AuthenticationException)` | The one method that issues the "please authenticate" challenge |
| `LoginUrlAuthenticationEntryPoint` | What `.loginPage()` builds by default |
| `AccessDeniedHandler.handle(request, response, AccessDeniedException)` | The *separate* path for authenticated-but-forbidden requests |
| `AccessDeniedHandlerImpl` / `.setErrorPage(String)` | Default implementation; forwards to a URL while preserving the 403 status |
| `HttpSecurity.exceptionHandling(Customizer<ExceptionHandlingConfigurer<HttpSecurity>>)` | Wires custom entry point / access-denied handler explicitly |
| `.authorizeHttpRequests(auth -> auth.requestMatchers(...).hasRole(...))` | Minimal scaffold, this topic only — real authorization is Group 3's subject |

### `src/main/java/com/labs/formauth/authentication/LabAuthenticationEntryPoint.java`
```java
package com.labs.formauth.authentication;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.io.IOException;

// Wraps exactly what .loginPage("/login") built invisibly since Topic 2.1 -
// same real object underneath, instrumented at the precise handoff point.
public class LabAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final AuthenticationEntryPoint delegate;

    public LabAuthenticationEntryPoint(String loginFormUrl) {
        this.delegate = new LoginUrlAuthenticationEntryPoint(loginFormUrl);
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                          AuthenticationException authException) throws IOException, ServletException {
        // This IS ExceptionTranslationFilter calling us, right after it cleared
        // the SecurityContext and saved the request (Topic 2.8's save point).
        System.out.println("[2.9] entry point commencing - exception class: "
                + authException.getClass().getSimpleName());
        System.out.println("[2.9] originally requested: " + request.getMethod() + " " + request.getRequestURI());

        delegate.commence(request, response, authException);

        System.out.println("[2.9] redirect issued -> " + response.getHeader("Location"));
    }
}
```

### `src/main/java/com/labs/formauth/authentication/RestApiAuthenticationEntryPoint.java`
```java
package com.labs.formauth.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.util.Map;

// TOGGLE-ONLY contrast. Proves the entry point is fully pluggable and has
// no obligation to redirect at all - a REST client gets a machine-readable
// 401, not an HTML redirect to a login page it can't render.
public class RestApiAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                          AuthenticationException authException) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(
                Map.of("error", "unauthorized", "message", authException.getMessage())));
        // No Location header anywhere in this response.
    }
}
```

### `src/main/java/com/labs/formauth/authentication/LabAccessDeniedHandler.java`
```java
package com.labs.formauth.authentication;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;

import java.io.IOException;
import java.util.Optional;

// A COMPLETELY DIFFERENT object from LabAuthenticationEntryPoint above -
// this only runs for an authenticated, non-anonymous principal who is
// missing a specific permission. formLogin() has no involvement here at all.
public class LabAccessDeniedHandler implements AccessDeniedHandler {

    private final AccessDeniedHandlerImpl delegate = new AccessDeniedHandlerImpl();

    public LabAccessDeniedHandler() {
        delegate.setErrorPage("/403"); // forwards here, preserving 403 status
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                        AccessDeniedException accessDeniedException) throws IOException, ServletException {
        String principal = Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
                .map(a -> a.getName())
                .orElse("none");
        System.out.println("[2.9] AccessDeniedHandler invoked (NOT the entry point) - principal: " + principal);
        System.out.println("[2.9] denied reason: " + accessDeniedException.getMessage());

        delegate.handle(request, response, accessDeniedException);
    }
}
```

### `src/main/java/com/labs/formauth/authentication/ExceptionHandlingConfig.java`
```java
package com.labs.formauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration
public class ExceptionHandlingConfig {

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new LabAuthenticationEntryPoint("/login");

        // TOGGLE for the contrast experiment below:
        // return new RestApiAuthenticationEntryPoint();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new LabAccessDeniedHandler();
    }
}
```

### `src/main/java/com/labs/formauth/web/AdminController.java`
```java
package com.labs.formauth.web;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

// Minimal trigger point ONLY - just enough authorization to produce a real
// AccessDeniedException for this topic. Full authorization rules, matcher
// types, and role hierarchies remain Group 3's subject.
@RestController
public class AdminController {

    @GetMapping("/admin")
    @ResponseBody
    public String admin(Authentication authentication) {
        return "Welcome, admin " + authentication.getName();
    }
}
```

### `src/main/java/com/labs/formauth/web/ErrorPagesController.java`
```java
package com.labs.formauth.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ErrorPagesController {

    @GetMapping("/403")
    public String forbidden() {
        return "403";
    }
}
```

### `src/main/resources/templates/403.html`
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Forbidden</title></head>
<body>
<h1>403 — Forbidden</h1>
<p>You're logged in, but you don't have permission to view that page.</p>
<p><a href="/">Home</a></p>
</body>
</html>
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
                                            AccessDeniedHandler accessDeniedHandler) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/debug/**", "/403").permitAll()
                // Minimal scaffold for THIS topic only - gives us a real
                // authenticated-but-forbidden case to trigger AccessDeniedHandler.
                .requestMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .authenticationManager(authenticationManager)
            .requestCache(cache -> cache.requestCache(requestCache))
            .exceptionHandling(ex -> ex
                // Explicit now - takes priority over whatever formLogin()
                // would otherwise build implicitly from .loginPage() below.
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
            .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
```

### Run it

```
mvn spring-boot:run
```

**Case 1 — no identity at all (the entry point path):**
```
curl -v http://localhost:8081/profile
```
Console:
```
[2.9] entry point commencing - exception class: InsufficientAuthenticationException
[2.9] originally requested: GET /profile
[2.9] redirect issued -> http://localhost:8081/login
```
*(The exact class name is what `AnonymousAuthenticationFilter`'s placeholder token produces when denied — read it straight off your own console rather than trusting this description.)*

**Case 2 — real identity, wrong permission (the access-denied path):**
```
curl -c cookies.txt -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123" -v
curl -b cookies.txt http://localhost:8081/admin -v
```
Console:
```
[2.9] AccessDeniedHandler invoked (NOT the entry point) - principal: alice
[2.9] denied reason: Access Denied
```
**Expected HTTP:** `403`, body is your rendered `403.html` — **no `Location` header anywhere in this response.** No `[2.9] entry point commencing` line prints at all. This is Part A's central claim, proven: two completely separate objects, triggered by two completely separate conditions.

### Contrast experiment — swap the entry point, watch the other path stay untouched

Toggle `ExceptionHandlingConfig` to `new RestApiAuthenticationEntryPoint()`, restart:
```
curl -v http://localhost:8081/profile
```
**Expected:** `401`, JSON body, no `Location` header — Case 1's behavior completely changed.
```
curl -b cookies.txt http://localhost:8081/admin -v
```
**Expected:** identical to before — still `403`, still your custom `403.html`, still the `[2.9] AccessDeniedHandler` console line. Swapping the entry point had zero effect on this path, because they are genuinely independent objects reacting to genuinely independent conditions.

### Try it yourself

1. Remove `.accessDeniedHandler(accessDeniedHandler)` from `.exceptionHandling(...)` (keep the entry point wired) and repeat Case 2. You should get Boot's plain whitelabel `403` instead of your template — confirming your custom handler, not some blanket setting, produced the friendly page.
2. Temporarily delete the `.requestMatchers("/admin").hasRole("ADMIN")` line so `/admin` falls under the plain `anyRequest().authenticated()` rule, log in as `alice`, and hit `/admin` again. It now succeeds with `200`. This isolates that the `403` in Case 2 came specifically from the role check — not from visiting `/admin` at all.
3. Log out (or use a fresh cookie jar) and hit `/admin` directly, with zero authentication. Which console line prints — `[2.9] entry point commencing` or `[2.9] AccessDeniedHandler invoked`? This confirms Part A's "anonymous is treated as needs-to-log-in" branch, even on a URL that's ultimately about roles, not just authentication.

### Delta

**Added:** `authentication/LabAuthenticationEntryPoint.java`, `authentication/RestApiAuthenticationEntryPoint.java`, `authentication/LabAccessDeniedHandler.java`, `authentication/ExceptionHandlingConfig.java`, `web/AdminController.java`, `web/ErrorPagesController.java`, `templates/403.html`
**Modified:** `config/SecurityConfig.java`