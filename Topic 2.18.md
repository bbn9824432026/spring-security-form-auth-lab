# Topic 2.18 — Multiple `SecurityFilterChain` beans & `@Order`

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** Every topic since 2.1 has configured exactly *one* `SecurityFilterChain`, and it's been applied to every single request in this project, uniformly. But a single `HttpSecurity` builder has exactly one CSRF setting, one session policy, one entry point — it cannot express "browser-facing pages need full form login with sessions and CSRF" *and* "a machine-facing API space needs something completely different" at the same time. Those are genuinely incompatible security postures for the same builder to hold simultaneously.

**☕ API Mapping:** `FilterChainProxy` — the very object underlying the "VirtualFilterChain" you first met in Group 1 — was never actually holding *one* chain. It holds an **ordered list** of `SecurityFilterChain` objects, each carrying its own `RequestMatcher`. For every incoming request, it walks that list **in order** and runs *only* the filters belonging to the **first** chain whose matcher matches. Every other request — the ones that don't need `/api/**`, say — never touches that chain's filters at all; they aren't skipped mid-execution, they're never entered in the first place.

---

**⚠️ The trap — and it's the same "list order determines everything" lesson you've now hit three separate times (2.3's providers, 2.12's logout handlers, now entire chains):** a chain with no explicit `.securityMatcher(...)` defaults to matching **everything**. If that unscoped chain is registered *before* a narrower one, the narrow chain becomes permanently unreachable — every request, including ones meant for it, gets swallowed by the broad chain first, since "first match wins" is a strict, linear scan with no fallback.

**☕ API Mapping — what actually controls the list order:** `@Order(n)` on each `@Bean SecurityFilterChain` method. Lower numbers are checked first. The narrowly-scoped chain has to carry the lower number; the catch-all chain, with no matcher at all, has to come last.

---

**🌍 Real World:** Building a second, genuinely independent chain for a stateless API space is also the first legitimate, *correct* reason in this entire course to disable CSRF — worth contrasting directly against Topic 2.1's lazy shortcut.

**☕ API Mapping:** CSRF exists to defend against a browser's **automatic, ambient** cookie attachment being exploited cross-site (2.10). An HTTP Basic-authenticated, `SessionCreationPolicy.STATELESS` chain has no cookie-based authentication at all — nothing a forged cross-site request could ride on. Disabling CSRF here isn't skipping a protection; it's recognizing the protection doesn't apply to this threat model at all.

**Deeper mechanism — what does and doesn't get shared between two chains:** `HttpSecurity` is handed to each `@Bean` method as a genuinely fresh, independent builder instance per injection — that's why configuring one chain never corrupts the other. But the beans you *inject into* both methods — `AuthenticationManager`, and everything wired into it — are ordinary Spring beans, and nothing stops two chains from sharing the exact same one. Sharing your `AuthenticationManager` (2.3/2.16/2.17) across both chains means the lockout guard and the audit listeners apply to *every* login attempt against these accounts, regardless of which chain received the request. What is **not** shared, by design, is each chain's own `AuthenticationEntryPoint` and `AccessDeniedHandler` — HTTP Basic's own default challenge behavior has nothing to do with the custom `LoginUrlAuthenticationEntryPoint` wrapper built in 2.9; that customization lives entirely inside the form-login chain and never runs for `/api/**`.

**How to observe all of this directly:** Part B hits both chains directly, checks for the *absence* of a session cookie on one and its *presence* on the other, then deliberately swaps the `@Order` values to watch the trap happen on command.

| Real-world question | Mechanism |
|---|---|
| What was `FilterChainProxy` actually holding this whole time? | An ordered list of chains, not one chain — this project just never needed more than one entry |
| What decides which chain a request gets routed to? | First matching `RequestMatcher`, in `@Order` sequence — strict, linear |
| What happens to an unscoped chain registered first? | It swallows everything meant for chains after it |
| Is disabling CSRF here the same mistake as Topic 2.1? | No — this chain has no cookie-based auth at all, so the threat CSRF defends against doesn't exist here |
| What's shared between chains vs. chain-specific? | `AuthenticationManager` and its guts: shareable. `AuthenticationEntryPoint`/`AccessDeniedHandler`: chain-specific by default |

---

## Part B — Lab

**Modules touched:** `config/`, `web/`

### API surface covered this topic

| API | Purpose |
|---|---|
| `@Order(n)` on a `@Bean SecurityFilterChain` method | Position in `FilterChainProxy`'s ordered list |
| `HttpSecurity.securityMatcher(String...)` | Scopes a chain to a URL subset; omitting it defaults to matching everything |
| `SessionCreationPolicy.STATELESS` | No session ever created for this chain, regardless of what happens |
| `HttpSecurity.httpBasic(Customizer<HttpBasicConfigurer>)` | A second, completely independent authentication mechanism |
| Sharing an `AuthenticationManager` bean across chains | Normal and often desirable — one identity source, multiple entry mechanisms |

### `src/main/java/com/labs/formauth/web/ApiController.java`
```java
package com.labs.formauth.web;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

    @GetMapping("/api/whoami")
    public String whoami(Authentication authentication) {
        return "[2.18] API chain - authenticated as " + authentication.getName()
                + ", authorities=" + authentication.getAuthorities();
    }
}
```

### `src/main/java/com/labs/formauth/config/SecurityConfig.java` (modified — now two chains)
```java
package com.labs.formauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.RequestCache;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // FIRST in FilterChainProxy's list. MUST be scoped narrowly - an
    // unscoped chain defaults to matching everything, which would make
    // this chain swallow requests meant for the one below it too.
    @Order(1)
    @Bean
    public SecurityFilterChain apiFilterChain(HttpSecurity http,
                                               AuthenticationManager authenticationManager) throws Exception {
        http
            .securityMatcher("/api/**")
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            // SAME AuthenticationManager as the form-login chain below -
            // same UserDetailsService, same DaoAuthenticationProvider, same
            // lockout guard (2.17), same audit listeners (2.16). One
            // identity source, two independent entry mechanisms.
            .authenticationManager(authenticationManager)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // Correctly disabled - see Part A. Not Topic 2.1's shortcut.
            .csrf(csrf -> csrf.disable())
            .httpBasic(basic -> {});

        return http.build();
    }

    // SECOND. No .securityMatcher() call at all - its default scope really
    // is "everything," which is exactly correct PROVIDED it stays after
    // the narrower chain above. Everything else here is unchanged since
    // Topic 2.17.
    @Order(2)
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
                                            UserDetailsService userDetailsService) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/debug/**", "/403").permitAll()
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
                .tokenValiditySeconds(1209600)
                .rememberMeParameter("remember-me")
                .userDetailsService(userDetailsService)
            );

        return http.build();
    }
}
```

### Run it

```
mvn spring-boot:run
```

**No credentials at all:**
```
curl -v http://localhost:8081/api/whoami
```
**Expected:** `401`, header `WWW-Authenticate: Basic realm="Realm"` — HTTP Basic's *own* default challenge, not a `302` to `/login`. This chain never touches `LabAuthenticationEntryPoint` (2.9) at all.

**Correct Basic credentials:**
```
curl -u alice:password123 -v http://localhost:8081/api/whoami
```
**Expected:** `200`, body confirming `alice`/`[ROLE_USER]`, and — check carefully with `-v` — **no `Set-Cookie` header anywhere in the response.** `SessionCreationPolicy.STATELESS` means exactly that.

**Confirm `/` is completely untouched by any of this:**
```
curl -v http://localhost:8081/
```
**Expected:** still a `302` to `/login`, the same behavior as every prior topic — proving the two chains genuinely answer to different rules for different URL spaces.

**Confirm the shared `AuthenticationManager` — lock alice out via the API chain, then via the browser chain:**
```
for i in 1 2 3; do curl -s -u alice:WRONGPASS http://localhost:8081/api/whoami -o /dev/null -w "%{http_code}\n"; done
```
Console: `[2.17] recordFailure - alice failureCount=3, NOW LOCKED until ...`. Now try the **correct** password through the **other** chain entirely:
```
T=$(curl -s http://localhost:8081/login | grep -oP '(?<=name="_csrf" value=")[^"]*')
curl -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123&_csrf=$T" -v
```
**Expected:** still blocked — `[2.17] BLOCKED before password check`. Three wrong Basic-auth attempts against `/api/**` just locked out a *browser* login attempt on a completely separate chain, because both chains share the same underlying identity machinery.

### Contrast experiment — reproduce the ordering trap directly

Swap the two `@Order` values (`apiFilterChain` becomes `@Order(2)`, `filterChain` becomes `@Order(1)`), restart:
```
curl -u alice:password123 -v http://localhost:8081/api/whoami
```
**Expected: a `302 Location: /login`, not a `200`.** Because the now-unscoped, now-first chain (`filterChain`, `@Order(1)`) matches *every* URL including `/api/whoami`, and it's checked before the API chain ever gets a turn. The `Authorization: Basic ...` header is simply never inspected by anything — this request never reaches `httpBasic()`'s filter at all. Revert the `@Order` values once confirmed.

### Try it yourself

1. With the correct `@Order` restored, remove `.securityMatcher("/api/**")` entirely from `apiFilterChain` (leave `@Order(1)` as-is). Restart and hit `curl http://localhost:8081/` with no credentials. Does it now return `401` instead of redirecting to `/login`? This isolates that the *matcher*, not just the order number, is what scopes a chain correctly.
2. Hit `/admin` through the API chain: `curl -u dave:password123 http://localhost:8081/admin`. It should fail — `/admin` was never included in `apiFilterChain`'s matcher (`/api/**` only), so this request falls through to the *second* chain regardless, and `isFullyAuthenticated()` from Topic 2.15 still applies exactly as before, unaffected by anything built in this topic.
3. Add a third chain, `@Order(0)` (checked before both existing ones), scoped to `.securityMatcher("/debug/**")`, with `.permitAll()` and no authentication requirement of any kind. Confirm `/debug/session` still works with zero credentials — then check whether it still shares the same `SessionRegistry`/`AuthenticationManager` beans as the other two chains, proving a third completely independent security posture can coexist with the two already built.

### Delta

**Added:** `web/ApiController.java`
**Modified:** `config/SecurityConfig.java` (split into two `@Order`-annotated chains: `apiFilterChain` for `/api/**`, `filterChain` for everything else)