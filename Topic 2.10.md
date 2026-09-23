# Topic 2.10 — CSRF protection mechanics

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** A browser attaches cookies to a request based purely on the **destination domain** — it does not care, and has no way to know, which page or site triggered that request. If `attacker.example` serves a page containing a hidden `<form action="http://localhost:8081/profile/update" method="post">` that auto-submits itself, and the victim's browser happens to be holding a valid session cookie for `localhost:8081` at that moment, the browser dutifully attaches that cookie to the cross-site submission. Your server has no way to distinguish that request from one your own `login.html` genuinely produced — both arrive as `POST /profile/update` with a valid session cookie.

**⚠️ What broke without this protection — concretely, right now, in your own project:** `/profile/update` (built in Topic 2.8) has taken exactly this shape since it was written, and CSRF has been disabled since Topic 2.1. That's not a hypothetical — it's the exact state your app is in as this topic begins. Part B proves the attack against your own running server before fixing anything.

**One precise nuance, often garbled:** the Same-Origin Policy does **not** block a cross-origin page from *submitting* a form. It blocks that page from *reading the response*, and from reading the DOM of a page served by another origin. An attacker's page can fire the POST blind — it never needs to see your `/login` page's HTML to do it. CSRF protection exists specifically to close the one gap SOP leaves open: submitting without reading.

---

**🌍 Real World:** To tell a legitimate request apart from a blind cross-origin one, the server needs something the attacker's page structurally cannot have obtained — not because it's secret in the "encrypted" sense, but because getting it requires *reading* a response from your origin, which SOP already blocks for them.

**☕ API Mapping:** `CsrfFilter` sits in the chain and, for any "unsafe" method (its internal matcher excludes only `GET`, `HEAD`, `TRACE`, `OPTIONS`), compares a token the request must submit against the one the server actually issued. `CsrfTokenRepository` is where that expected value is generated and persisted — `HttpSessionCsrfTokenRepository`, the default, writes it into the `HttpSession`.

**⚠️ The trap this creates on its own — the reason "forms break without it" is this topic's own subtitle:** the instant CSRF is turned back on, your own `/perform_login` form — built in 2.1, never updated since — has no token field at all. It becomes indistinguishable, to `CsrfFilter`, from an attacker's blind submission. Re-enabling CSRF the naive way locks *you* out first.

---

**🌍 Real World:** If the server just embedded the same fixed token value into every page for the life of a session, and the connection is served over HTTPS with compression enabled, an attacker who can get their own content reflected into a response alongside that token can use a known technique — repeatedly guessing one byte at a time and watching compressed response size shrink when the guess is right — to extract the token without ever directly reading it. This is the real, named **BREACH** attack.

**☕ API Mapping:** Since Spring Security 6.0, the default `CsrfTokenRequestHandler` is `XorCsrfTokenRequestAttributeHandler` — confirmed current, not a guess. The underlying token stored in the repository stays stable per session, but every time it's published for use in a page, it's XORed with a fresh random value first. The result is a *different-looking* token string on every single page load, even within the same unchanged session, which defeats BREACH's byte-guessing approach outright.

**Deeper mechanism, closing a loop from your other project's Topic 1.4:** the published token isn't computed eagerly. `CsrfFilter` installs it as a **deferred supplier** under the request attribute name `_csrf`. Nothing forces the underlying repository interaction — no session write, no cookie — until something *actually calls* `.getToken()` on it. A page that never references the token triggers none of this. A page that does (like a form rendering `${_csrf.token}`) is what causes the real save to happen. Same deferred-loading philosophy as `SecurityContextHolderFilter`'s explicit-save model — here applied to a completely different object.

**How to observe this directly:** Part B builds two side-by-side endpoints — one that touches the token, one that doesn't — and you check for `Set-Cookie: JSESSIONID` on each with your own eyes, not a description.

| Real-world question | Mechanism |
|---|---|
| Why can't a cross-site page just fake the request? | SOP blocks *reading* your origin's responses; it can only submit blind |
| What actually gets compared? | `CsrfFilter` vs. `CsrfTokenRepository`-stored value, on every non-safe method |
| Why does the visible token change on every page load? | `XorCsrfTokenRequestAttributeHandler` — default since 6.0, BREACH mitigation |
| Why doesn't a plain API GET create a session just because CSRF is on? | Deferred supplier — resolution only happens if something calls `.getToken()` |

---

## Part B — Lab

**Modules touched:** `authentication/`, `web/`, `config/`, `templates/`

### API surface covered this topic

| API | Purpose |
|---|---|
| `CsrfFilter` | Enforces token match on unsafe methods; publishes the deferred token on every request |
| `CsrfTokenRepository` / `HttpSessionCsrfTokenRepository` | Where the real token value is generated and stored |
| `CookieCsrfTokenRepository.withHttpOnlyFalse()` | Alternative repository — token in a JS-readable cookie, for SPA/API clients |
| `CsrfTokenRequestHandler` / `XorCsrfTokenRequestAttributeHandler` | Publishes the token per-request with BREACH-safe masking; default since 6.0 |
| `CsrfToken` (interface) | `getToken()`, `getHeaderName()`, `getParameterName()` — what a controller can inject directly |
| `HttpSecurity.csrf(Customizer<CsrfConfigurer<HttpSecurity>>)` | Entry point — was `.disable()` since 2.1; now configured properly |

### Step 1 — prove the vulnerability against your own running app, as-is

CSRF is still disabled from Topic 2.1. Don't change anything yet.

```
mvn spring-boot:run
```
```
curl -c cookies.txt -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123" -v
```
Now simulate the attacker's blind form submission — a fresh request, no knowledge of any token, just the cookie a real browser would attach automatically:
```
curl -b cookies.txt -X POST http://localhost:8081/profile/update -d "bio=HACKED_BY_ATTACKER" -v
```
**Expected:** `200`, and the console prints `[2.8] POST /profile/update ACTUALLY EXECUTED for alice, bio=HACKED_BY_ATTACKER`. This is a real, working attack against real code you've had running since Topic 2.8 — not a description of one.

### `src/main/java/com/labs/formauth/authentication/CsrfConfig.java`
```java
package com.labs.formauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

@Configuration
public class CsrfConfig {

    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        return new HttpSessionCsrfTokenRepository();

        // CONTRAST TOGGLE: for SPA/JS clients that need to read the token
        // themselves (no server-rendered <form> to inject it into) - see
        // the contrast experiment below.
        // return org.springframework.security.web.csrf.CookieCsrfTokenRepository.withHttpOnlyFalse();
    }
}
```

### `src/main/java/com/labs/formauth/web/CsrfDebugController.java`
```java
package com.labs.formauth.web;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// Debug-only, permitAll. Spring resolves CsrfToken as a controller argument
// directly - and calling .getToken() on it HERE is exactly the act that
// resolves the deferred supplier from Part A.
@RestController
public class CsrfDebugController {

    @GetMapping("/debug/csrf")
    public String showCsrfToken(CsrfToken token) {
        return "[2.10] headerName=" + token.getHeaderName()
                + " | parameterName=" + token.getParameterName()
                + " | token=" + token.getToken();
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
                                            CsrfTokenRepository csrfTokenRepository) throws Exception {
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
            // FINALLY turned back on, as promised since Topic 2.1. Explicit
            // repository wiring, even though HttpSessionCsrfTokenRepository
            // is also the implicit default - stated so it's visible.
            .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository));

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

<form action="/perform_login" method="post">
    <!--
      RAW manual wiring - no sec: dialect yet (Topic 2.11 replaces this with
      automatic injection). ${_csrf} resolves because Thymeleaf's Spring
      integration exposes request attributes directly, and
      XorCsrfTokenRequestAttributeHandler published this one before this
      template ever started rendering. Evaluating ${_csrf.token} right here
      is what triggers the deferred token to actually be saved (Part A).
    -->
    <input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}"/>

    <label>Username: <input type="text" name="user"/></label><br/>
    <label>Password: <input type="password" name="pass"/></label><br/>
    <button type="submit">Log in</button>
</form>
</body>
</html>
```

### Step 2 — apply the fix, then reproduce the break the fix itself causes

Restart with the changes above. First, try logging in the *old* way (exactly like every previous topic's curl command):
```
curl -c cookies.txt -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123" -v
```
**Expected:** `403 Forbidden`, body mentioning a missing/invalid CSRF token. This is Part A's central trap, made real — the fix that closes the attacker's path also breaks your own unmodified request.

### Step 3 — the correct flow, done at the raw HTTP level

```
curl -c cookies.txt http://localhost:8081/login -o login_page.html -v
TOKEN=$(grep -oP '(?<=name="_csrf" value=")[^"]*' login_page.html)
echo "extracted token: $TOKEN"

curl -b cookies.txt -c cookies.txt -X POST http://localhost:8081/perform_login \
  -d "user=alice&pass=password123&_csrf=$TOKEN" -v
```
**Expected:** `302`, successful login — same credentials, same endpoint, now with the token your own `login.html` actually rendered.

### Step 4 — reattempt the attack from Step 1, now that the fix is live

```
curl -b cookies.txt -X POST http://localhost:8081/profile/update -d "bio=HACKED_AGAIN" -v
```
**Expected:** `403`. Same valid session cookie that worked in Step 1 now fails outright — the token requirement is exactly the piece the attacker's blind cross-origin form could never have supplied.

### Contrast experiment — deferred loading, proven with two endpoints side by side

```
curl -c never_touches_csrf.txt http://localhost:8081/debug/saved-request -v 2>&1 | grep -i set-cookie
```
**Expected:** no output — no `Set-Cookie` header at all. `/debug/saved-request` (built in 2.8) never references the CSRF token, so the deferred supplier is never resolved, so nothing is ever written to a session.

```
curl -c touches_csrf.txt http://localhost:8081/debug/csrf -v 2>&1 | grep -i set-cookie
```
**Expected:** a real `Set-Cookie: JSESSIONID=...` line. `CsrfDebugController` calls `token.getToken()` directly — that single method call is what forced the session into existence.

### Try it yourself

1. Toggle `CsrfConfig` to `CookieCsrfTokenRepository.withHttpOnlyFalse()`. Restart, hit `GET /debug/csrf`, and check response headers for a new cookie named `XSRF-TOKEN`. Compare its value against what `/debug/csrf`'s body reports — same value, different transport, exactly the shape an SPA's JS would need to read it and attach it as a header on its own `fetch()` calls.
2. Repeat Step 3's full login flow twice in a row without deleting `login_page.html` — reuse the *first* extracted `$TOKEN` value against a freshly fetched session cookie from a second, separate `GET /login`. Does it still work? This tells you directly whether the token is tied to the session or is a bare standalone secret.
3. Remove the `<input type="hidden" ...>` line from `login.html` entirely but leave CSRF enabled in `SecurityConfig`. Attempt Step 3's login flow again. Confirm the failure message this time is about a *missing* token rather than an *invalid* one — two distinct exception paths inside `CsrfFilter` for two genuinely different problems.

### Delta

**Added:** `authentication/CsrfConfig.java`, `web/CsrfDebugController.java`
**Modified:** `config/SecurityConfig.java` (`.csrf(csrf -> csrf.disable())` removed, explicit repository wired), `templates/login.html` (raw CSRF hidden field added)