# Topic 2.15 — Remember-Me authentication

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** Everything built so far dies the moment the session does — close the browser, come back tomorrow, and the session cookie (if non-persistent) is simply gone; log in again. "Remember me" has to survive something a normal session can't: a completely fresh request, days later, with *zero* session state of any kind, that still gets recognized without re-entering a password. That means the proof of identity has to live somewhere that outlives the session entirely — a second, independent, long-lived cookie carrying enough information to reconstruct authentication from scratch.

**☕ API Mapping:** `RememberMeAuthenticationFilter` sits in the chain specifically *after* the normal login mechanisms. Its entire job: if the `SecurityContext` is still empty after everything else has had a chance to populate it (nobody logged in via a fresh POST on this request), check for a remember-me cookie and, if valid, build an `Authentication` from it directly — no session-based login step involved at all.

---

**🌍 Real World:** What actually goes *inside* that cookie, and how it's checked, are two genuinely different engineering choices with different failure modes.

**☕ API Mapping — Option 1, `TokenBasedRememberMeServices` (stateless, the DSL default):** the cookie is `base64(username : expiryTime : signature)`, where `signature` is a hash computed from the username, the expiry, the user's **current** password (fetched fresh via `UserDetailsService`), and a server-side secret key. Validating means recomputing that same hash and comparing — nothing is stored anywhere.

**Deeper mechanism — a genuinely useful side effect:** because the signature depends on the *current* password, changing a password instantly invalidates every remember-me cookie for that account, everywhere, with no extra code. Part B proves this directly.

**⚠️ The trap:** that same design has exactly one shared secret — the server-side key — protecting *every account at once*. If it leaks (hardcoded, checked into source control, guessed), anyone who knows a target's username can forge a valid cookie for that account without ever touching its password. Simplicity and single-point-of-failure are the same property here, not a trade-off between two different things.

---

**☕ API Mapping — Option 2, `PersistentTokenBasedRememberMeServices` (stateful):** the cookie carries only `series : token` — two random values, no username, no password-derived anything. A `PersistentTokenRepository` holds the real record: series, current token, username, last-used time. On every remember-me-driven request, the filter looks up the series, compares the submitted token, authenticates on match — and then **immediately generates a brand-new token for that same series**, overwrites the stored value, and issues a fresh cookie. Same series, new token, every single time it's used.

**Deeper mechanism — why rotate on *every* use, not just on password change:** this is a deliberate defense against a stolen cookie sitting unused. If an attacker copies the cookie value and the real user's browser happens to use it *first*, the legitimate use rotates the token — the attacker's copy is now a **series match with a token mismatch**. `PersistentTokenBasedRememberMeServices` treats that specific combination as evidence of theft, not a bug to silently ignore: it deletes **every** token for that account, killing the whole remember-me chain for both parties, forcing a real login. This is genuinely clever, deliberate design — the mismatch itself becomes the detector.

**⚠️ A real, honest limitation, worth knowing rather than discovering in production:** two genuinely legitimate devices sharing the same account's remember-me chain can trigger this same "theft" response against each other — whichever one is offline longest, when it finally reconnects and presents its now-stale token, looks identical to a stolen cookie from the repository's point of view. This isn't a flaw to fix; it's the reason each device really wants its own login rather than a shared, exported remember-me cookie.

---

**🌍 Real World:** From the point of view of a plain `.authenticated()` check, a request recognized purely by a six-week-old remember-me cookie looks *identical* to one where the person just typed their password thirty seconds ago. For some actions — changing account settings, viewing sensitive data, reaching `/admin` — that distinction genuinely matters.

**☕ API Mapping:** the reconstructed `Authentication` object has a distinct concrete type, `RememberMeAuthenticationToken`, and `AuthenticationTrustResolver.isRememberMe(authentication)` checks exactly this. The authorization-side equivalent is `isFullyAuthenticated()` (SpEL) — it returns `false` for a remember-me-derived authentication, even with every role and authority correctly attached.

**⚠️ The trap, and it's easy to miss entirely:** `.hasRole("ADMIN")` alone says nothing about *how* that role was established. dave, with `ROLE_ADMIN`, recognized purely by an old remember-me cookie, sails straight through a bare `.hasRole("ADMIN")` check. Only `isFullyAuthenticated()`, checked explicitly, catches the difference.

**How to observe all of this directly:** Part B builds a `/debug/whoami` endpoint printing the real `Authentication` class and trust-resolver results, and a password-change utility to watch a `TokenBasedRememberMeServices` cookie die live.

| Real-world question | Mechanism |
|---|---|
| What survives after the session itself is gone? | A separate cookie, checked by `RememberMeAuthenticationFilter` when the context is empty |
| Stateless variant — what's the cookie, what's the risk? | `TokenBasedRememberMeServices` — password-derived signature; one shared key protects every account |
| Stateful variant — what's the cookie, what's the risk? | `PersistentTokenBasedRememberMeServices` — random series+token, rotated every use, theft detected via mismatch |
| Is remember-me-authenticated the same as freshly-logged-in? | No — `RememberMeAuthenticationToken` + `isFullyAuthenticated()` tells them apart |

---

## Part B — Lab

**Modules touched:** `authentication/`, `web/`, `config/`, `templates/`

### API surface covered this topic

| API | Purpose |
|---|---|
| `RememberMeAuthenticationFilter` | Reconstructs `Authentication` from the cookie when the context is otherwise empty |
| `RememberMeServices` (interface) | `loginSuccess()` (issue cookie), `autoLogin()` (validate it), also a `LogoutHandler` |
| `TokenBasedRememberMeServices` | Stateless — password-derived signature |
| `PersistentTokenRepository` / `PersistentTokenBasedRememberMeServices` | Stateful — rotating token, theft detection |
| `HttpSecurity.rememberMe(Customizer<RememberMeConfigurer>)` | `.key()`, `.tokenValiditySeconds()`, `.userDetailsService()`, `.tokenRepository()` |
| `AuthenticationTrustResolver.isRememberMe(Authentication)` | Tells a remembered login apart from a fresh one |
| `WebExpressionAuthorizationManager` + `isFullyAuthenticated()` | Requires a genuinely fresh login, not merely "authenticated" |

### `src/main/java/com/labs/formauth/authentication/InMemoryPersistentTokenRepository.java`
```java
package com.labs.formauth.authentication;

import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// STATIC, in-memory - no real database, matching this course's convention.
// Demonstrates the PersistentTokenRepository CONTRACT and the rotation /
// theft-detection behavior it enables. A real system would back this with
// an actual table.
public class InMemoryPersistentTokenRepository implements PersistentTokenRepository {

    private final Map<String, PersistentRememberMeToken> tokensBySeries = new ConcurrentHashMap<>();

    @Override
    public void createNewToken(PersistentRememberMeToken token) {
        System.out.println("[2.15] createNewToken - series=" + token.getSeries()
                + ", username=" + token.getUsername());
        tokensBySeries.put(token.getSeries(), token);
    }

    @Override
    public void updateToken(String series, String tokenValue, Date lastUsed) {
        PersistentRememberMeToken existing = tokensBySeries.get(series);
        if (existing == null) return;
        // THIS is the rotation from Part A - same series, brand-new token,
        // on every single successful remember-me authentication.
        System.out.println("[2.15] updateToken (ROTATION) - series=" + series + ", newToken=" + tokenValue);
        tokensBySeries.put(series, new PersistentRememberMeToken(
                existing.getUsername(), series, tokenValue, lastUsed));
    }

    @Override
    public PersistentRememberMeToken getTokenForSeries(String seriesId) {
        return tokensBySeries.get(seriesId);
    }

    @Override
    public void removeUserTokens(String username) {
        // THIS is the theft-response - wipes EVERY token for the account,
        // not just the offending one.
        System.out.println("[2.15] removeUserTokens (THEFT DETECTED or logout) - username=" + username);
        tokensBySeries.values().removeIf(t -> t.getUsername().equals(username));
    }
}
```

### `src/main/java/com/labs/formauth/authentication/RememberMeConfig.java`
```java
package com.labs.formauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

@Configuration
public class RememberMeConfig {

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        return new InMemoryPersistentTokenRepository();
    }
}
```

### `src/main/java/com/labs/formauth/web/DebugController.java` (modified — added `whoami` and a lab-only password changer)
```java
package com.labs.formauth.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
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
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    public DebugController(RequestCache requestCache, SessionRegistry sessionRegistry,
                            UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.requestCache = requestCache;
        this.sessionRegistry = sessionRegistry;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/debug/saved-request")
    public String showSavedRequest(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest saved = requestCache.getRequest(request, response);
        if (saved == null) return "[2.8] no saved request in this session";
        String params = saved.getParameterMap().entrySet().stream()
                .map(e -> e.getKey() + "=" + String.join(",", e.getValue()))
                .collect(Collectors.joining("; "));
        return "[2.8] method=" + saved.getMethod() + " | redirectUrl=" + saved.getRedirectUrl()
                + " | parameters={" + params + "}";
    }

    @GetMapping("/debug/session")
    public String showSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) return "[2.12] no session exists for this request";
        return "[2.12] session exists - id=" + session.getId();
    }

    @GetMapping("/debug/sessions/{username}")
    public String showSessionsForUser(@PathVariable String username) {
        for (Object principal : sessionRegistry.getAllPrincipals()) {
            String principalName = (principal instanceof UserDetails ud) ? ud.getUsername() : principal.toString();
            if (principalName.equals(username)) {
                List<SessionInformation> sessions = sessionRegistry.getAllSessions(principal, true);
                if (sessions.isEmpty()) return "[2.14] registry has principal but no session entries";
                return sessions.stream()
                        .map(si -> "sessionId=" + si.getSessionId() + ", expired=" + si.isExpired())
                        .collect(Collectors.joining("\n"));
            }
        }
        return "[2.14] no registry entries found for " + username;
    }

    // Added in 2.15 - direct proof of WHAT kind of Authentication this
    // request actually has, distinguishing a fresh login from remember-me.
    @GetMapping("/debug/whoami")
    public String whoami(Authentication authentication) {
        if (authentication == null) return "[2.15] no authentication in context";
        return "[2.15] class=" + authentication.getClass().getSimpleName()
                + " | name=" + authentication.getName()
                + " | isRememberMe=" + trustResolver.isRememberMe(authentication)
                + " | authorities=" + authentication.getAuthorities();
    }

    // LAB ONLY - never expose password changes over a bare GET in real code.
    // Exists purely to prove TokenBasedRememberMeServices invalidates on
    // password change, live, without building a real settings UI.
    @GetMapping("/debug/change-password/{username}/{newPassword}")
    public String changePassword(@PathVariable String username, @PathVariable String newPassword) {
        UserDetailsManager manager = (UserDetailsManager) userDetailsService;
        UserDetails current = manager.loadUserByUsername(username);
        UserDetails updated = User.withUserDetails(current)
                .password(passwordEncoder.encode(newPassword))
                .build();
        manager.updateUser(updated);
        return "[2.15] password updated for " + username;
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
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
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
                                            SessionRegistry sessionRegistry,
                                            UserDetailsService userDetailsService,
                                            PersistentTokenRepository persistentTokenRepository) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/debug/**", "/403").permitAll()
                // Changed in 2.15: plain hasRole("ADMIN") would let a
                // remember-me-only dave straight through. This requires a
                // GENUINELY fresh login too - see Part A's trap.
                .requestMatchers("/admin").access(
                        new WebExpressionAuthorizationManager("hasRole('ADMIN') and isFullyAuthenticated()"))
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
                session.maximumSessions(1)
                        .maxSessionsPreventsLogin(true)
                        .expiredUrl("/login?expired-session")
                        .sessionRegistry(sessionRegistry);
            })
            .rememberMe(rememberMe -> rememberMe
                .key("formAuthLabRememberMeKey")
                .tokenValiditySeconds(1209600) // 14 days
                .rememberMeParameter("remember-me")
                .userDetailsService(userDetailsService)
                // CONTRAST TOGGLE: uncomment to switch from stateless
                // TokenBasedRememberMeServices to stateful
                // PersistentTokenBasedRememberMeServices - see Part A/lab.
                // .tokenRepository(persistentTokenRepository)
            );

        return http.build();
    }
}
```

### `src/main/resources/templates/login.html` (modified — remember-me checkbox)
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
    <label><input type="checkbox" name="remember-me"/> Remember me</label><br/>
    <button type="submit">Log in</button>
</form>
</body>
</html>
```

### Run it — stateless variant (default, as configured above)

```
mvn spring-boot:run
```
```
T=$(curl -s http://localhost:8081/login | grep -oP '(?<=name="_csrf" value=")[^"]*')
curl -c full_cookies.txt -X POST http://localhost:8081/perform_login \
  -d "user=alice&pass=password123&remember-me=true&_csrf=$T" -v
```
Check for the cookie: `grep remember-me full_cookies.txt` — a real, separate cookie, distinct from `JSESSIONID`.

**Simulate closing the browser** — carry over *only* the remember-me cookie into a brand-new jar, discarding the session entirely:
```
grep remember-me full_cookies.txt > /tmp/rm_line
cat /tmp/rm_line > remember_only.txt   # a fresh jar with no JSESSIONID at all
curl -b remember_only.txt http://localhost:8081/profile
curl -b remember_only.txt http://localhost:8081/debug/whoami
```
**Expected:** the profile page renders successfully, and:
```
[2.15] class=RememberMeAuthenticationToken | name=alice | isRememberMe=true | authorities=[ROLE_USER]
```
No session ever existed for this request — this is the whole mechanism, proven end to end.

**The `/admin` trap — try it as dave:**
```
T2=$(curl -s http://localhost:8081/login | grep -oP '(?<=name="_csrf" value=")[^"]*')
curl -c dave_cookies.txt -X POST http://localhost:8081/perform_login \
  -d "user=dave&pass=password123&remember-me=true&_csrf=$T2" -v
grep remember-me dave_cookies.txt > dave_remember_only.txt
curl -b dave_remember_only.txt http://localhost:8081/admin -v
```
**Expected: `403`**, even though dave genuinely has `ROLE_ADMIN` — `isFullyAuthenticated()` fails for a `RememberMeAuthenticationToken`, exactly as Part A predicted.

### Contrast experiment — password change kills the cookie

```
curl http://localhost:8081/debug/change-password/alice/newpassword456
curl -b remember_only.txt http://localhost:8081/profile -v
```
**Expected:** redirected to `/login` — the remember-me cookie you just proved worked is now dead, purely from a password change, with nothing else touched.

### Contrast experiment — switch to the stateful variant, prove theft detection

Uncomment `.tokenRepository(persistentTokenRepository)`, restart, log in as alice with remember-me again. Console shows `[2.15] createNewToken`. Simulate the browser-restart request from before:
```
curl -b remember_only.txt -c remember_only.txt http://localhost:8081/profile -v
```
Console shows `[2.15] updateToken (ROTATION)` — and the `Set-Cookie` in the response carries a **new** remember-me value. Now replay the **old**, pre-rotation cookie (saved from the original login, before this rotation):
```
curl -b full_cookies.txt http://localhost:8081/profile -v
```
**Expected:** console shows `[2.15] removeUserTokens (THEFT DETECTED or logout)` — and this request fails. Now try the legitimately rotated cookie from the step before:
```
curl -b remember_only.txt http://localhost:8081/profile -v
```
**Expected:** it *also* now fails — the theft response wiped the entire chain, exactly as Part A described, not just the stale copy.

### Try it yourself

1. Repeat the stateless-variant flow, but log out (2.12's flow) instead of changing the password. Then retry `remember_only.txt` against `/profile`. Does logout also kill the remember-me cookie? This confirms whether `RememberMeServices`'s automatic addition to the logout handler chain actually did its job.
2. In the persistent variant, log in as alice on two *separate* simulated devices (two separate cookie jars from two separate logins — two different series). Use one device once (triggering rotation), then check that the *other* device's remember-me cookie is completely unaffected — confirming rotation and theft-detection are scoped per series, not per account.
3. Change `.tokenValiditySeconds(1209600)` to `.tokenValiditySeconds(5)`. Wait 6 seconds, then try `remember_only.txt` against `/profile`. Confirm it fails purely on expiry — no password change, no logout, no theft — just the clock.

### Delta

**Added:** `authentication/InMemoryPersistentTokenRepository.java`, `authentication/RememberMeConfig.java`
**Modified:** `web/DebugController.java` (`/debug/whoami`, `/debug/change-password/...`), `config/SecurityConfig.java` (`.rememberMe(...)` added, `/admin` rule tightened), `templates/login.html` (remember-me checkbox)