# Topic 2.6 — `AuthenticationSuccessHandler`

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** Authentication just succeeded — 2.3's provider chain returned a verified token. Something now has to physically write bytes back over the TCP connection the browser's POST arrived on. But "what should happen on success" is not one universal answer: a traditional server-rendered app wants a `302` redirect somewhere; a single-page app talking to this same endpoint via `fetch()` wants a `200` with a JSON body; an app with a "you tried to open a specific page before logging in" flow wants to send the browser back to *that exact page*, not a fixed one. The filter that just finished verifying credentials has no business deciding which of these your app needs.

**☕ API Mapping:** That decision is fully delegated to `AuthenticationSuccessHandler` — one method, `onAuthenticationSuccess(request, response, authentication)`, no return value. It writes directly to `HttpServletResponse` itself. Whatever it does — or doesn't do — to that response object *is* the entire outcome.

---

**🌍 Real World:** In Topic 2.1, `.defaultSuccessUrl("/", false)` looked like a simple two-argument setting. It's actually sugar over a real object being constructed and installed for you.

**☕ API Mapping:** That call builds a `SavedRequestAwareAuthenticationSuccessHandler` and quietly calls `.successHandler(...)` with it — same field, same mechanism you'll use directly in this lab. Internally, it does exactly three things: ask a `RequestCache` (default: `HttpSessionRequestCache`) whether a `SavedRequest` exists for this session; if `alwaysUseDefaultTargetUrl` is `true`, ignore that entirely; otherwise, redirect to the saved request's URL if one exists, or fall back to the default target. The actual byte-level redirect — the `302` status and `Location` header — is written by a `RedirectStrategy`, and the default implementation of *that* is nothing more exotic than calling `response.sendRedirect(url)`.

---

**🌍 Real World:** Look at where this handler sits in the sequence of things that happen after a successful login. The `SecurityContext` gets built and saved to the session — the exact mechanism from your other project's 1.4 topic, `HttpSessionSecurityContextRepository` — *before* this handler ever runs. The success handler is the **last** thing that happens, not the first.

**⚠️ The trap:** because context-saving happens earlier and independently, a custom success handler that throws an exception, hangs, or otherwise misbehaves doesn't undo the authentication. The browser might get a `500` error page from your broken handler — but the session cookie it's holding is already fully authenticated underneath that error. This surprises people who assume "the login failed" whenever they see an error screen after submitting the form.

**How to observe this directly:** the lab below deliberately breaks a success handler *after* printing a confirmation line, then proves the session is authenticated anyway by hitting a protected page with the same cookie in a second request.

| Real-world question | Mechanism |
|---|---|
| What decides the response on success? | `AuthenticationSuccessHandler.onAuthenticationSuccess()` |
| What did `.defaultSuccessUrl()` actually build? | `SavedRequestAwareAuthenticationSuccessHandler` — checks `RequestCache`, falls back to a fixed URL |
| What physically writes the redirect? | `RedirectStrategy` → `response.sendRedirect(url)` |
| Is the session already authenticated when this handler runs? | Yes — `SecurityContextRepository.saveContext()` (1.4) already ran before this handler is called |

---

## Part B — Lab

**Modules touched:** `authentication/`, `config/`

### API surface covered this topic

| API | Purpose |
|---|---|
| `AuthenticationSuccessHandler` (interface) | The one method every strategy implements |
| `SimpleUrlAuthenticationSuccessHandler` | Base class with target-URL resolution logic |
| `SavedRequestAwareAuthenticationSuccessHandler` | What `.defaultSuccessUrl()` builds under the hood |
| `RequestCache` / `HttpSessionRequestCache` | Where a pre-login deep link is stashed (full depth: 2.8) |
| `RedirectStrategy` / `DefaultRedirectStrategy` | The object that actually calls `response.sendRedirect(...)` |
| `FormLoginConfigurer.successHandler(AuthenticationSuccessHandler)` | Wires a custom handler, replacing `.defaultSuccessUrl()` |

### `src/main/java/com/labs/formauth/authentication/LabAuthenticationSuccessHandler.java`
```java
package com.labs.formauth.authentication;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;

// This IS what .defaultSuccessUrl("/", false) built invisibly in Topic 2.1 -
// written out by hand so every decision is visible.
public class LabAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final String defaultTargetUrl = "/";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                         Authentication authentication) throws IOException, ServletException {

        // By the time this line runs, SecurityContextRepository.saveContext()
        // (Group 1's 1.4 mechanism) has ALREADY persisted the session. This
        // handler runs LAST, not first - see the Try It Yourself trap below.
        System.out.println("[2.6] success handler running for: " + authentication.getName());
        System.out.println("[2.6] authorities: " + authentication.getAuthorities());

        // Exactly what SavedRequestAwareAuthenticationSuccessHandler checks
        // internally. Full RequestCache mechanics: Topic 2.8.
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        if (savedRequest != null) {
            String targetUrl = savedRequest.getRedirectUrl();
            System.out.println("[2.6] found saved request -> redirecting to " + targetUrl);
            redirectStrategy.sendRedirect(request, response, targetUrl);
            return;
        }

        System.out.println("[2.6] no saved request -> redirecting to default: " + defaultTargetUrl);
        redirectStrategy.sendRedirect(request, response, defaultTargetUrl);
    }
}
```

### `src/main/java/com/labs/formauth/authentication/JsonAuthenticationSuccessHandler.java`
```java
package com.labs.formauth.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.List;
import java.util.Map;

// TOGGLE-ONLY contrast (see SuccessHandlerConfig). Proves onAuthenticationSuccess
// is not obligated to redirect at all - a real requirement for SPA/API clients
// expecting a JSON body, not a 302.
public class JsonAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                         Authentication authentication) throws IOException {

        List<String> authorities = authentication.getAuthorities().stream()
                .map(Object::toString)
                .toList();

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(
                Map.of("status", "ok", "username", authentication.getName(), "authorities", authorities)
        ));
        // No redirect, no Location header. The entire "where do we send the
        // browser" question this topic covers simply doesn't apply here.
    }
}
```

### `src/main/java/com/labs/formauth/authentication/SuccessHandlerConfig.java`
```java
package com.labs.formauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
public class SuccessHandlerConfig {

    @Bean
    public AuthenticationSuccessHandler successHandler() {
        return new LabAuthenticationSuccessHandler();

        // TOGGLE: comment the line above, uncomment below, to see a
        // completely non-redirecting success handler in action instead.
        // return new JsonAuthenticationSuccessHandler();
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
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                            AuthenticationManager authenticationManager,
                                            AuthenticationSuccessHandler successHandler) throws Exception {
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
                .successHandler(successHandler)   // replaces .defaultSuccessUrl() from 2.1
                .failureUrl("/login?error")
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

**Deep-link case:**
```
curl -c cookies.txt http://localhost:8081/profile -v   # unauthenticated -> 302 to /login, saves the request
curl -b cookies.txt -c cookies.txt -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123" -v
```
Console:
```
[2.6] success handler running for: alice
[2.6] authorities: [ROLE_USER]
[2.6] found saved request -> redirecting to http://localhost:8081/profile
```
`Location: http://localhost:8081/profile` — not `/`. This is Part A's claim, proven with your own request, not asserted.

**No deep link:** fresh cookie jar, `POST /perform_login` directly without visiting `/profile` first:
```
[2.6] no saved request -> redirecting to default: /
```

### Contrast experiment — the DSL-order trap

Add both calls to the same `formLogin(...)` block and watch which one wins based purely on order:

**Variant A — custom handler wins (called last):**
```java
.defaultSuccessUrl("/somewhere-else", true)
.successHandler(successHandler)
```
Login as alice → `[2.6]` prints appear, redirect goes where your handler decided.

**Variant B — custom handler silently discarded (called last is `defaultSuccessUrl`):**
```java
.successHandler(successHandler)
.defaultSuccessUrl("/somewhere-else", true)
```
Login as alice → **no `[2.6]` output at all.** The browser always lands on `/somewhere-else`, regardless of any deep link, because `defaultSuccessUrl()` quietly built a *new* `SavedRequestAwareAuthenticationSuccessHandler` and overwrote the same field your `.successHandler(...)` call had just set. Same two lines, opposite outcome, purely from order.

### Try it yourself

1. Toggle `SuccessHandlerConfig` to return `new JsonAuthenticationSuccessHandler()` instead. Restart, repeat the curl login sequence, and inspect the raw response body — confirm it's a `200` with JSON, no `Location` header anywhere.
2. Reproduce both variants of the DSL-order contrast experiment yourself and confirm the presence/absence of `[2.6]` console output matches the explanation above.
3. In `LabAuthenticationSuccessHandler`, replace the final `redirectStrategy.sendRedirect(...)` call with `throw new RuntimeException("simulated failure");` right after the console prints. Restart, log in — the browser gets a `500`. Now, **reusing the same session cookie**, `curl -b cookies.txt http://localhost:8081/profile` — it succeeds with `200`. This proves the ordering trap directly: the session was authenticated before the broken handler ever ran, independent of whether the handler itself succeeded.

### Delta

**Added:** `authentication/LabAuthenticationSuccessHandler.java`, `authentication/JsonAuthenticationSuccessHandler.java`, `authentication/SuccessHandlerConfig.java`
**Modified:** `config/SecurityConfig.java` (`.defaultSuccessUrl()` replaced with `.successHandler(...)`)