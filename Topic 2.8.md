# Topic 2.8 — `RequestCache` / `SavedRequest`

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** The sequence "user tries to open a protected page → gets redirected to log in → logs in → lands back where they started" spans **three separate, stateless HTTP requests** with no inherent connection between them. HTTP itself has no concept of "this request is part of that earlier conversation." The only place that memory can physically live, across that gap, is server-side storage tied to a session cookie the browser keeps sending back.

**☕ API Mapping:** That storage is `RequestCache`. Its default implementation, `HttpSessionRequestCache`, does exactly what its name says — writes into the `HttpSession`.

---

**🌍 Real World:** *Where* does the "remembering" actually happen? It's tempting to assume `formLogin()` does it, since that's where you've spent six topics — but the memory has to be captured at the moment the original request gets **blocked**, which is earlier in the chain, before any login machinery is even involved.

**☕ API Mapping:** `ExceptionTranslationFilter` is the filter that catches the `AuthenticationException` thrown by an unauthenticated access attempt (the same mechanism behind `anyRequest().authenticated()` scaffolding you've had since 2.1). Before it invokes the `AuthenticationEntryPoint` — the exact object `.loginPage(...)` configured back in 2.1 — it calls `requestCache.saveRequest(request, response)`. This is the real save point, and it runs on *every* blocked request, regardless of whether that request was a `GET` or a `POST`.

**Deeper mechanism — what actually gets stored:** `HttpSessionRequestCache` wraps the blocked request into a `DefaultSavedRequest`, capturing far more than a URL string: the full reconstructed URL, the HTTP method, every header, every cookie, and the entire parameter map (`request.getParameterMap()` — which merges query-string values *and* POST body values into one map). This whole object gets written into the session.

---

**🌍 Real World:** After login succeeds and the browser is redirected back, that redirect is a brand-new `GET` request — but your controller might expect to see the *original* request's data (a specific `Accept` header, an original parameter) rather than whatever's on this bare replay request.

**☕ API Mapping:** `RequestCacheAwareFilter`, sitting further down the same chain, calls `requestCache.getMatchingRequest(...)` on every incoming request. If a saved request matches, it doesn't just let the plain request through — it substitutes a wrapper that merges the saved data back in, so `request.getParameter(...)` inside your controller can return a value that was never actually present on this specific `GET`'s query string.

**⚠️ The trap — and it's a real, common bug, not a corner case:** the *method* is never replayed. Only the URL is. If the original blocked request was a `POST` to an endpoint that changes something — submitting a form, saving an update — the redirect that "sends the user back where they were" is always a `GET`. If that endpoint only accepts `POST`, the replay fails outright (`405`). If it accepts both, the parameters *are* silently available via the merging wrapper above — but any code branching on `request.getMethod().equals("POST")` to decide whether to actually perform the action will silently skip it, because the method really is `GET` now. The user sees a page load; the action they submitted never runs.

**How to observe this directly:** rather than trust the description, Part B builds a `POST`-only endpoint, deliberately blocks it while unauthenticated, and inspects the actual `DefaultSavedRequest` contents through the real `RequestCache` API before ever following the replay redirect.

| Real-world question | Mechanism |
|---|---|
| Where does memory of "what they tried to reach" live across 3 separate requests? | Server-side session, via `RequestCache` |
| Who actually captures it, and when? | `ExceptionTranslationFilter`, at the moment it catches the `AuthenticationException` — before the login page is even shown |
| What's stored — just a URL? | No — `DefaultSavedRequest`: full URL, method, headers, cookies, entire parameter map |
| How does it get merged back into the replayed request? | `RequestCacheAwareFilter` wraps the incoming request with cached data |
| What's never replayed? | The HTTP method itself — the redirect is always a `GET` |

---

## Part B — Lab

**Modules touched:** `authentication/`, `web/`, `config/`

### API surface covered this topic

| API | Purpose |
|---|---|
| `RequestCache` (interface) | `saveRequest()`, `getRequest()`, `getMatchingRequest()`, `removeRequest()` |
| `HttpSessionRequestCache` | Default implementation, session-backed |
| `HttpSessionRequestCache.setRequestMatcher(RequestMatcher)` | Excludes matching requests from ever being saved |
| `DefaultSavedRequest` / `SavedRequest` | What's actually stored — method, redirect URL, headers, parameter map |
| `NullRequestCache` | No-op implementation — disables deep-link replay entirely (used in the contrast experiment) |
| `HttpSecurity.requestCache(Customizer<RequestCacheConfigurer<HttpSecurity>>)` | Wires a custom `RequestCache` into the chain |

### `src/main/java/com/labs/formauth/authentication/RequestCacheConfig.java`
```java
package com.labs.formauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;

@Configuration
public class RequestCacheConfig {

    @Bean
    public RequestCache requestCache() {
        HttpSessionRequestCache cache = new HttpSessionRequestCache();

        // Real production concern: an XHR/fetch call that hits a protected
        // endpoint and gets redirected should NOT be remembered as "the
        // page the user wanted" - replaying an API call as a full-page GET
        // navigation later makes no sense. saveRequest() silently no-ops
        // when this matcher returns false. There is NO such exclusion by
        // default - HttpSessionRequestCache matches everything unless told
        // otherwise, which is exactly what this bean changes.
        cache.setRequestMatcher(request ->
                !"XMLHttpRequest".equals(request.getHeader("X-Requested-With")));

        return cache;

        // CONTRAST TOGGLE: replace the block above with the single line
        // below to disable deep-link replay entirely - useful for APIs
        // where "always land on a fixed URL" is actually the desired behavior.
        // return new org.springframework.security.web.savedrequest.NullRequestCache();
    }
}
```

### `src/main/java/com/labs/formauth/web/UpdateProfileController.java`
```java
package com.labs.formauth.web;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

// Throwaway trigger point only - a POST-only, state-changing endpoint,
// exists purely to reproduce the "method is never replayed" trap.
@RestController
public class UpdateProfileController {

    @PostMapping("/profile/update")
    public String updateProfile(@RequestParam("bio") String bio, Authentication authentication) {
        System.out.println("[2.8] POST /profile/update ACTUALLY EXECUTED for "
                + authentication.getName() + ", bio=" + bio);
        return "Profile updated for " + authentication.getName() + ": " + bio;
    }
}
```

### `src/main/java/com/labs/formauth/web/DebugController.java`
```java
package com.labs.formauth.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.stream.Collectors;

// Debug-only, permitAll - exists purely to make RequestCache's internal
// state observable instead of taken on faith. Never ship this in a real app.
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
import org.springframework.security.web.savedrequest.RequestCache;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                            AuthenticationManager authenticationManager,
                                            AuthenticationSuccessHandler successHandler,
                                            AuthenticationFailureHandler failureHandler,
                                            RequestCache requestCache) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                // scaffolding for this topic's inspection endpoints only -
                // matcher semantics in depth remain Group 3's subject.
                .requestMatchers("/debug/**").permitAll()
                .anyRequest().authenticated()
            )
            .authenticationManager(authenticationManager)
            // Explicit now - was an invisible default since Topic 2.1.
            .requestCache(cache -> cache.requestCache(requestCache))
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

**Step 1 — block a POST while unauthenticated:**
```
curl -c cookies.txt -X POST http://localhost:8081/profile/update -d "bio=Hello world" -v
```
Expected: `302 Location: /login`. No `[2.8] ... EXECUTED` line in the console — the update never ran.

**Step 2 — inspect what actually got saved, before touching login:**
```
curl -b cookies.txt http://localhost:8081/debug/saved-request
```
Expected:
```
[2.8] method=POST | redirectUrl=http://localhost:8081/profile/update | parameters={bio=Hello world}
```
This confirms Part A's claim directly — the POST body's parameter really is sitting in the saved request, method and all.

**Step 3 — log in:**
```
curl -b cookies.txt -c cookies.txt -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123" -v
```
Console (from 2.6's handler): `[2.6] found saved request -> redirecting to http://localhost:8081/profile/update`.

**Step 4 — follow the replay exactly as the browser would:**
```
curl -b cookies.txt http://localhost:8081/profile/update -v
```
**Expected: `405 Method Not Allowed`.** The replay is always a `GET`; `@PostMapping` doesn't accept it. This is the trap, reproduced end to end — the "helpful" redirect sent the browser to the exact URL it originally wanted, and it still fails.

### Contrast experiment — the AJAX exclusion, proven

```
curl -c cookies.txt -X GET http://localhost:8081/profile -H "X-Requested-With: XMLHttpRequest" -v
curl -b cookies.txt http://localhost:8081/debug/saved-request
```
**Expected:** `[2.8] no saved request in this session` — the matcher in `RequestCacheConfig` blocked the save entirely. Now repeat without the header:
```
curl -c cookies2.txt -X GET http://localhost:8081/profile -v
curl -b cookies2.txt http://localhost:8081/debug/saved-request
```
**Expected:** a real saved request appears — `method=GET | redirectUrl=.../profile`. Same code path, one header flips the outcome, exactly as the matcher was configured to do.

### Try it yourself

1. Comment out the `cache.setRequestMatcher(...)` line entirely (plain `new HttpSessionRequestCache()`), rerun the AJAX-header test — the saved request now appears *despite* the header, proving the exclusion was your configuration, not Spring's default behavior.
2. Change `RequestCacheConfig` to return `new NullRequestCache()` (the contrast toggle in the comment). Rerun Steps 1–3 above — the success handler's console output should now always say `no saved request -> redirecting to default: /`, regardless of what was blocked beforehand.
3. Change `UpdateProfileController`'s mapping to `@RequestMapping(value = "/profile/update", method = {RequestMethod.GET, RequestMethod.POST})`, repeat Step 4 — it now returns `200` instead of `405`. Check the console: does `bio=Hello world` still print, even though this request's actual query string never contained it? That's `RequestCacheAwareFilter`'s parameter-merging at work, on a request that is, underneath, a bare `GET`.

### Delta

**Added:** `authentication/RequestCacheConfig.java`, `web/UpdateProfileController.java`, `web/DebugController.java`
**Modified:** `config/SecurityConfig.java` (explicit `.requestCache(...)`, `/debug/**` permitted)