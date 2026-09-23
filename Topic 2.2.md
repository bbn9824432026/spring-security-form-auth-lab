# Topic 2.2 — `UsernamePasswordAuthenticationFilter` internals

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** Every single request that comes through your app — `GET /`, `GET /profile`, `POST /perform_login`, all of it — passes through the *same* filter object. Spring beans are singletons; there's one instance of this filter sitting in the chain, and it runs on every request, not just login attempts. What it does on each request is almost always nothing: a cheap string comparison against the path and HTTP method. Only when both match does it do any real work.

**☕ API Mapping:** That comparison is a `RequestMatcher` — a small object holding a compiled path pattern and a method, evaluated by calling `.matches(request)`. When you set `.loginProcessingUrl("/perform_login")` in 2.1, you were configuring exactly this matcher's pattern. This is the literal implementation of `requiresAuthentication(request, response)` inside the filter's parent class, `AbstractAuthenticationProcessingFilter`.

---

**🌍 Real World:** The match succeeds — this request really is `POST /perform_login`. The servlet container already parsed the POST body into a parameter map (it does this lazily, the first time anything calls `getParameter`). The filter now needs to turn "two strings sitting in a map" into something the rest of Spring Security can pass around as a first-class concept — because from here on, nothing else in the chain wants to think in terms of raw HTTP parameters.

**☕ API Mapping:** `obtainUsername(request)` and `obtainPassword(request)` are just `request.getParameter("user")` / `request.getParameter("pass")` under the hood — the same parameter names you configured in 2.1. Those two strings get wrapped into a `UsernamePasswordAuthenticationToken`, built via a static factory: `UsernamePasswordAuthenticationToken.unauthenticated(username, password)`. The name is deliberate — this token is explicitly marked as *not yet verified*.

**Deeper mechanism, one layer down:** `Authentication` (the interface this token implements) carries a boolean `authenticated` flag internally. `.unauthenticated(...)` sets it `false`. There's a separate factory, `.authenticated(...)`, that sets it `true` — and that flag is exactly what `SecurityContextHolder` and every downstream authorization check trusts. Nothing re-verifies it later.

**⚠️ The trap:** if you ever hand-write a custom authentication filter (a common thing to do for JWT, API keys, SSO callbacks, etc. — not this topic, but you'll get there eventually) and you call `.authenticated(principal, credentials, authorities)` directly, without ever routing through an `AuthenticationManager`, you have just told Spring Security "trust this, no questions asked" — for *any* value in `credentials`, verified or not. This isn't a hypothetical: it's a real, documented footgun, and it's exactly why the two factory methods exist as *separate, differently-named* calls instead of one constructor with a boolean parameter that's easy to flip by accident.

---

**🌍 Real World:** The filter now has an unverified token. It doesn't check anything itself — it has no idea what a correct password looks like, and it shouldn't; that's a separate concern with its own machinery (2.3).

**☕ API Mapping:** `return this.getAuthenticationManager().authenticate(authRequest);` — one line. Everything before it was extraction and packaging; this line is the entire handoff. Whatever comes back — a fully verified `Authentication` with `authenticated=true` and real `GrantedAuthority` objects, or a thrown `AuthenticationException` — is what the rest of the filter reacts to.

---

**🌍 Real World:** Two branches, same as Part A of 2.1 predicted, but now you can see *where* they're decided: back inside `AbstractAuthenticationProcessingFilter`, after `attemptAuthentication()` returns or throws.

**☕ API Mapping:** Success → `successfulAuthentication(...)`, which stores the verified `Authentication` into `SecurityContextHolder` and saves it via the `SecurityContextRepository` (the exact mechanism you already built in your other project's 1.4 topic — same interface, same responsibility, different project). Failure → `unsuccessfulAuthentication(...)`, which clears the context and hands the exception to a failure handler (2.7).

**How to observe this directly:** DEBUG logging (already on) shows this filter's class name in the log lines around every login attempt. But the sharpest way to see it is to watch the actual values at each step yourself — which is exactly what Part B's lab does: a subclass that prints at the precise lines Part A just walked through.

| Real-world step | Mechanism |
|---|---|
| Is this even a login request? | `RequestMatcher.matches()` — cheap path+method check, runs on every request |
| Turn two strings into one object | `obtainUsername()` / `obtainPassword()` → `UsernamePasswordAuthenticationToken.unauthenticated(...)` |
| Hand off for verification | `AuthenticationManager.authenticate(authRequest)` |
| React to the outcome | `successfulAuthentication()` (saves context) or `unsuccessfulAuthentication()` (clears context) |

---

## Part B — Lab

**Modules touched:** `authentication/` (new — first use), `config/`

### API surface covered this topic

| API | Purpose |
|---|---|
| `AbstractAuthenticationProcessingFilter.requiresAuthentication()` | Cheap path+method gate; everything else is skipped if this is false |
| `UsernamePasswordAuthenticationFilter.obtainUsername()` / `obtainPassword()` | Raw parameter extraction, `protected` so subclasses can hook in |
| `UsernamePasswordAuthenticationToken.unauthenticated(principal, credentials)` | Builds an explicitly-not-yet-verified token |
| `UsernamePasswordAuthenticationToken.authenticated(principal, credentials, authorities)` | Builds an explicitly-verified token — **never call this yourself without going through an `AuthenticationManager` first** |
| `Authentication.isAuthenticated()` | The trusted flag every downstream check relies on |
| `HttpSecurity.addFilterAt(filter, atClass)` | Places a filter instance at another filter class's canonical chain position |
| `AuthenticationConfiguration.getAuthenticationManager()` | How you obtain the real `AuthenticationManager` bean when wiring a filter by hand |
| `setFilterProcessesUrl()`, `setUsernameParameter()`, `setPasswordParameter()`, `setAuthenticationSuccessHandler()`, `setAuthenticationFailureHandler()` | The imperative (non-DSL) equivalents of everything `.formLogin()` configured in 2.1 |

### `src/main/java/com/labs/formauth/authentication/InstrumentedUsernamePasswordAuthenticationFilter.java`
```java
package com.labs.formauth.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// This IS the real class .formLogin() built for you invisibly in Topic 2.1.
// We're subclassing it purely to print at the exact moments Part A described —
// nothing about the actual authentication behavior changes.
public class InstrumentedUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        // obtainUsername/obtainPassword = request.getParameter(...) under the hood.
        // This only runs at all because requiresAuthentication() already matched
        // path + method — that gate happened before this method was ever called.
        String username = obtainUsername(request);
        String password = obtainPassword(request);
        System.out.println("[2.2] extracted from POST body -> username='" + username
                + "', password present=" + (password != null));

        // super.attemptAuthentication() is where UsernamePasswordAuthenticationToken
        // .unauthenticated(username, password) gets built, then handed straight to
        // AuthenticationManager.authenticate(...). Everything happens inside this
        // one call - Topic 2.3 is what happens on the other side of it.
        Authentication result = super.attemptAuthentication(request, response);

        System.out.println("[2.2] AuthenticationManager returned -> "
                + result.getClass().getSimpleName()
                + ", authenticated=" + result.isAuthenticated()
                + ", authorities=" + result.getAuthorities());
        System.out.println("[2.2] attached details -> " + result.getDetails());
        // getDetails() is a WebAuthenticationDetails object — remote IP + session ID —
        // attached automatically, useful later for audit logging (Topic 2.16).

        return result;
    }
}
```

### `src/main/java/com/labs/formauth/config/DebugSecurityConfig.java`
```java
package com.labs.formauth.config;

import com.labs.formauth.authentication.InstrumentedUsernamePasswordAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// GLASS-BOX variant. Everything .formLogin() did declaratively in 2.1,
// done here by hand, object by object, so the internals are visible.
//
// TO RUN THIS: comment out the @Configuration annotation (and the whole
// filterChain bean) in SecurityConfig.java first — only one SecurityFilterChain
// covering "any request" can be active at a time. Revert when you're done.
@Configuration
@EnableWebSecurity
public class DebugSecurityConfig {

    @Bean
    public SecurityFilterChain debugFilterChain(HttpSecurity http,
                                                 AuthenticationConfiguration authConfig) throws Exception {

        // This is the exact same AuthenticationManager formLogin() would have
        // used internally — you're just obtaining it explicitly instead of
        // letting the DSL do it invisibly.
        var authenticationManager = authConfig.getAuthenticationManager();

        var authFilter = new InstrumentedUsernamePasswordAuthenticationFilter();
        authFilter.setAuthenticationManager(authenticationManager);
        authFilter.setFilterProcessesUrl("/perform_login");   // same as loginProcessingUrl()
        authFilter.setUsernameParameter("user");               // same as usernameParameter()
        authFilter.setPasswordParameter("pass");               // same as passwordParameter()
        authFilter.setAuthenticationSuccessHandler(
                (request, response, authentication) -> response.sendRedirect("/"));
        authFilter.setAuthenticationFailureHandler(
                (request, response, exception) -> response.sendRedirect("/login?error"));

        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login").permitAll()   // formLogin() did this automatically via permitAll();
                                                          // by hand, you have to list it yourself
                .anyRequest().authenticated()
            )
            // Places our filter at the exact chain position
            // UsernamePasswordAuthenticationFilter normally occupies.
            .addFilterAt(authFilter, UsernamePasswordAuthenticationFilter.class)
            .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
```

### Run it

Comment out the `filterChain` bean (or the `@Configuration` annotation) in `SecurityConfig.java`, restart, then:

```
curl -v -c cookies.txt -X POST http://localhost:8081/perform_login \
  -d "user=alice&pass=password123"
```

**Expected console output** (from your subclass, in this order):
```
[2.2] extracted from POST body -> username='alice', password present=true
[2.2] AuthenticationManager returned -> UsernamePasswordAuthenticationToken, authenticated=true, authorities=[ROLE_USER]
[2.2] attached details -> WebAuthenticationDetails [RemoteIpAddress=127.0.0.1, SessionId=null]
```
**Expected curl output:** `< HTTP/1.1 302`, `< Location: /`, and a `Set-Cookie: JSESSIONID=...` header. Now prove the session actually carries that saved context:

```
curl -v -b cookies.txt http://localhost:8081/profile
```
Expected: `200 OK` with the profile HTML — the cookie alone is now enough, because `successfulAuthentication()` saved the context via the same `SecurityContextRepository` mechanism from your other project's 1.4 topic.

### Contrast experiment — the trap, made real

Add this throwaway insecure filter (never ship anything like it) to see exactly what happens when a token is marked `authenticated` without ever going through `AuthenticationManager.authenticate()`:

```java
// DO NOT USE OUTSIDE THIS EXPERIMENT.
authFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
    // Bypasses everything - builds an "authenticated" token directly from
    // whatever was typed, no password check happened anywhere.
    var fakeToken = org.springframework.security.authentication.UsernamePasswordAuthenticationToken
        .authenticated("mallory", "anything-at-all",
            java.util.List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER")));
    org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(fakeToken);
    response.sendRedirect("/");
});
```

Wire this in temporarily, submit *any* garbage username/password to `/perform_login`, and you'll land on `/profile` successfully — because nothing ever checked the password; the `.authenticated(...)` factory told Spring Security to trust it outright. Delete this after confirming it — it's here only to make the Part A trap undeniable rather than asserted.

### Try it yourself

1. Send a **GET** instead of POST: `curl -v http://localhost:8081/perform_login`. Notice none of the `[2.2]` print statements appear at all — the filter never even runs `attemptAuthentication()`, because `requiresAuthentication()` failed the method check before your code was ever reached.
2. Run the insecure contrast experiment above, then remove it and confirm `/perform_login` with garbage credentials now correctly fails again — proving the `AuthenticationManager` handoff, not the filter itself, is what actually enforces correctness.
3. Send `curl -c cookies.txt -X POST http://localhost:8081/perform_login -d "user=  alice  &pass=password123"` (padded username) — it still succeeds. Now try `-d "user=alice&pass= password123 "` (padded password) — it fails. Source-level reason: `attemptAuthentication()` calls `username.trim()` but never trims the password. Same filter, two different whitespace behaviors, by design.

### Delta

**Added:** `authentication/InstrumentedUsernamePasswordAuthenticationFilter.java`, `config/DebugSecurityConfig.java`
**Modified:** none (toggle `SecurityConfig.java` manually to switch variants; no permanent change)