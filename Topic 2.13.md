# Topic 2.13 — Session fixation protection

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** A session ID is normally issued by the servlet container the *first* time something calls `request.getSession()` on a connection — completely independent of whether that visitor ever logs in. You've already seen this yourself: back in Topic 2.10, simply visiting `GET /login` (which renders `${_csrf.token}`) created a real session and issued a real `JSESSIONID`, before any credentials existed anywhere in the request. That pre-login session ID is sitting on the wire, in a cookie, right now, for any anonymous visitor.

**⚠️ What broke without protection against this — a real, historically significant attack class:** if nothing changes that ID at the moment of successful login, the *same* ID that existed before authentication becomes, unchanged, "the ID of an authenticated session." An attacker doesn't need to steal a password at all — they only need the victim's browser to end up holding an ID the attacker already knows. Classic delivery mechanisms include a crafted link containing a URL-rewritten session parameter, or a cookie written by a compromised sibling subdomain. This lab reproduces the *consequence* directly and faithfully — two separate cookie jars sharing one ID, exactly modeling "the victim's browser holds the attacker's planted value" — without needing to build the delivery mechanism itself, which is a separate, orthogonal problem.

---

**🌍 Real World:** To close this, something has to run at the exact moment authentication succeeds — not before, not after — and replace the session's identity while keeping everything already stored in it intact (by this point in your app, that session may already hold a CSRF token from 2.10 and a saved request from 2.8; losing either mid-login would break things you already built).

**☕ API Mapping:** `SessionAuthenticationStrategy.onAuthentication(authentication, request, response)` runs directly inside `AbstractAuthenticationProcessingFilter.successfulAuthentication()` — the same method from Topic 2.2 — called **before** the `SecurityContext` is attached to the session and **before** your `AuthenticationSuccessHandler` (2.6) ever runs. The default implementation, confirmed straight from Spring Security's own source: `ChangeSessionIdAuthenticationStrategy`.

**Deeper mechanism, one layer down:** it calls `HttpServletRequest.changeSessionId()` — a real Servlet 3.1 API added specifically for this purpose. Critically, this keeps the *same* underlying `HttpSession` object, with every attribute already stored in it, and only swaps the **key** that object is filed under in the container's session table. The old key becomes an instant dead end — a lookup against it returns nothing — while every attribute (your CSRF token, any saved request) survives completely untouched, because the object holding them was never destroyed.

**⚠️ The trap — and it's the same shape as 2.1's CSRF trap, reapplied:** `.sessionFixation().none()` disables this outright, with zero visible symptom during ordinary development — your app works exactly the same in every manual test you'd normally run. The vulnerability only becomes observable if you deliberately go looking for it, which is exactly what Part B does.

---

**🌍 Real World:** Before `changeSessionId()` existed as a servlet API (pre-Servlet-3.1 containers), the only way to achieve a similar effect was cruder: fully invalidate the old session, create a brand-new one, and manually copy over whichever attributes you wanted preserved.

**☕ API Mapping:** That older approach still exists as configurable alternatives on the same DSL: `.migrateSession()` (invalidate + new session + copy all attributes — momentarily zero active session object during the swap) and `.newSession()` (invalidate + new session + copy *nothing* — the most aggressive option, useful when you deliberately want zero carryover from an anonymous pre-login session).

**How to observe all of this directly:** you already built the exact tool for this in Topic 2.12 — `/debug/session`, which reports `session.getId()`. Part B uses it to print the real ID before and after login, in both the vulnerable and protected configurations, so the difference is a string comparison you make yourself, not a description you take on trust.

| Real-world question | Mechanism |
|---|---|
| When does the ID get replaced, relative to login? | Inside `successfulAuthentication()`, before the context is saved — same method from 2.2 |
| What replaces it by default? | `ChangeSessionIdAuthenticationStrategy` → `request.changeSessionId()` (Servlet 3.1) |
| Does anything stored in the session get lost? | No — same object, same attributes, only the lookup key changes |
| Older, cruder alternative | `.migrateSession()` / `.newSession()` — invalidate + recreate, with or without copying attributes |
| Disabling it | `.none()` — silent, symptomless in normal use, exploitable |

---

## Part B — Lab

**Modules touched:** `config/` only — this topic is pure configuration; `/debug/session` from 2.12 is reused as-is for observation.

### API surface covered this topic

| API | Purpose |
|---|---|
| `HttpSecurity.sessionManagement(Customizer<SessionManagementConfigurer>)` | Entry point |
| `.sessionFixation(Customizer<SessionFixationConfigurer>)` | Nested configurer for this specific concern |
| `.changeSessionId()` | Default — swaps the ID, preserves the same session object and its attributes |
| `.migrateSession()` | Legacy alternative — invalidate + new session + copy all attributes |
| `.newSession()` | Invalidate + new session + copy nothing |
| `.none()` | Disables fixation protection entirely — vulnerable, lab use only |
| `HttpServletRequest.changeSessionId()` (Servlet 3.1 API) | What `ChangeSessionIdAuthenticationStrategy` actually calls |

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
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessHandler(logoutSuccessHandler)
                .deleteCookies("JSESSIONID")
            )
            // Explicit now - was already the implicit default since Topic
            // 2.1. This is the FIX; the contrast experiment below is the
            // deliberately vulnerable variant, for demonstration only.
            .sessionManagement(session -> session
                .sessionFixation(fixation -> fixation.changeSessionId())
            );

        return http.build();
    }
}
```

### Step 1 — reproduce the attack against the deliberately vulnerable variant

Temporarily change the last line to `.sessionFixation(fixation -> fixation.none())`, restart.

```
mvn spring-boot:run
```

**Attacker primes a session** (models delivering a fixed ID to the victim — this lab reproduces the consequence, not the delivery vector itself):
```
curl -c attacker_cookies.txt http://localhost:8081/login -s -o /dev/null
grep JSESSIONID attacker_cookies.txt
```
Note the value — call it `PRE_ID`.

**Victim's browser ends up holding that same ID** (copy the file to model this):
```
cp attacker_cookies.txt victim_cookies.txt
curl -b victim_cookies.txt -c victim_cookies.txt http://localhost:8081/login -o login_page.html
TOKEN=$(grep -oP '(?<=name="_csrf" value=")[^"]*' login_page.html)
curl -b victim_cookies.txt -c victim_cookies.txt -X POST http://localhost:8081/perform_login \
  -d "user=alice&pass=password123&_csrf=$TOKEN" -v
grep JSESSIONID victim_cookies.txt
```
**Expected: the `JSESSIONID` value is identical to `PRE_ID`.** Login succeeded, but the session's identity never changed.

**Attacker reuses their original, never-modified cookie file:**
```
curl -b attacker_cookies.txt http://localhost:8081/debug/session
curl -b attacker_cookies.txt http://localhost:8081/profile
```
**Expected:** `[2.12] session exists - id=<PRE_ID>` and the actual, rendered profile page — **"Logged in as: alice."** The attacker never touched alice's password. This is the real attack, working end to end against your own code.

### Step 2 — restore the fix, reproduce the exact same steps

Change `.sessionFixation(fixation -> fixation.none())` back to `.sessionFixation(fixation -> fixation.changeSessionId())`, restart, repeat Step 1's commands verbatim.

**Expected difference #1:** `grep JSESSIONID victim_cookies.txt` after login now shows a **different** value from `PRE_ID`.

**Expected difference #2:**
```
curl -b attacker_cookies.txt http://localhost:8081/debug/session
```
`[2.12] no session exists for this request` — the pre-login ID is now a dead lookup key. And:
```
curl -b attacker_cookies.txt http://localhost:8081/profile
```
Redirected to `/login`. Same stolen cookie, same attacker, now completely useless.

### Contrast experiment — confirm attributes really do survive the ID swap

While running the *fixed* configuration, before logging in as the victim, hit a URL that populates something in the session first:
```
curl -b victim_cookies.txt -c victim_cookies.txt http://localhost:8081/profile -v   # blocked -> saves a request (2.8's mechanism)
curl -b victim_cookies.txt http://localhost:8081/debug/saved-request
```
Confirm a saved request is present. Now complete the login (as in Step 2). Immediately after:
```
curl -b victim_cookies.txt http://localhost:8081/debug/saved-request
```
**Expected:** the saved request is *still there*, under the brand-new session ID — direct, reproducible proof that `changeSessionId()` truly preserves attributes across the swap, exactly as Part A described, rather than wiping the slate the way `.newSession()` would.

### Try it yourself

1. Repeat the full attack from Step 1, but with `.sessionFixation(fixation -> fixation.newSession())` instead of `.none()`. Confirm the attack fails (same as `changeSessionId()`), but rerun the saved-request contrast experiment against this variant — does the saved request from before login survive this time? This isolates exactly what `newSession()` sacrifices that `changeSessionId()` doesn't.
2. With the fix active, log in as alice, note the post-login `JSESSIONID`, then immediately log out (2.12's flow) and log back in again with a *fresh* `curl -c` (no reused cookie at all). Compare the two post-login IDs — confirm they're different from each other, not just different from the pre-login one, showing a fresh ID is issued on every successful authentication, not just once per session lifetime.
3. Temporarily add `System.out.println` calls bracketing `.sessionFixation(...)` isn't possible directly (it's a stateless DSL call) — instead, hit `/debug/session` three times in the *vulnerable* (`.none()`) configuration: once before login, once immediately after, once five seconds later. Confirm the ID is identical all three times, proving `.none()` isn't just "delays" the change — it never happens at all.

### Delta

**Modified:** `config/SecurityConfig.java` (explicit `.sessionManagement(...)` added — no new files this topic)