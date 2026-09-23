# Topic 2.11 — Thymeleaf ⇄ Spring Security integration

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** Right now, `login.html`'s `<form action="/perform_login" method="post">` uses a **plain, static** `action` attribute — just a string Thymeleaf leaves untouched. The hidden CSRF field you added by hand in Topic 2.10 was necessary specifically *because* nothing was watching that attribute at render time.

**☕ API Mapping:** Switch that to `th:action="@{/perform_login}"` and something completely different happens. `th:action` is a real Thymeleaf attribute processor — specifically the Spring integration's `SpringActionTagProcessor`, bundled in `spring-boot-starter-thymeleaf` — and because the element is a `<form>`, this processor does one extra thing no other attribute triggers: it calls a genuine Spring MVC extension point, `RequestDataValueProcessor.getExtraHiddenFields(request)`, and appends whatever comes back right after the opening `<form>` tag, before any of your own markup.

**Deeper mechanism, one layer down — and this is the part that surprises people:** `RequestDataValueProcessor` has nothing to do with Spring Security by itself. It's a general-purpose Spring MVC hook. What makes CSRF fields appear automatically is that Spring Security auto-configures its own implementation of that interface — `CsrfRequestDataValueProcessor` — the moment CSRF protection is active. **The `thymeleaf-extras-springsecurity6` dialect you've had in `pom.xml` since this project's shell plays no role in this specific mechanism at all.** Three separate pieces — Thymeleaf's own Spring integration, a generic Spring MVC SPI, and a Spring Security bean — chain together to produce what looks like one seamless feature.

---

**⚠️ The trap, made concrete:** the mechanism only fires through `th:action`. A form written as plain `action="/perform_login"` — exactly what you had from Topic 2.1 through 2.10 — never touches `SpringActionTagProcessor` at all, so the hidden field never appears, no matter how correctly CSRF is configured server-side. This is *precisely* why your manual `<input type="hidden" th:name="${_csrf.parameterName}" .../>` in 2.10 was necessary, and it's exactly what this topic replaces.

**How to observe this directly:** view the raw HTML `/login` actually sends — not what you wrote, what got rendered — and look for the hidden field's exact position relative to the opening tag. Part B does this with `curl`, not a browser dev tool, so there's no ambiguity about what the server produced versus what a browser might rearrange.

---

**🌍 Real World:** Separately from CSRF, your `profile.html` (2.4) and `home.html` currently only know the logged-in user's name because a `@Controller` method explicitly pulled it off `Authentication` and stuffed it into a `Model`. Every page that wants to show *any* fact about who's logged in needs that same boilerplate repeated in its controller.

**☕ API Mapping:** *This* is where `thymeleaf-extras-springsecurity6` actually earns its place. It registers expression support directly inside Thymeleaf's own expression language: `sec:authentication="name"` reads `authentication.getName()` straight from the `SecurityContext` — no controller code, no `Model` attribute, nothing passed in from Java at all. `sec:authorize="hasRole('ADMIN')"` goes further — it evaluates a real security SpEL expression against a `SecurityExpressionRoot`, and if it's `false`, the element is **stripped from the DOM entirely** before the page is even serialized. Not hidden with CSS, not present-but-invisible — genuinely absent from the bytes sent to the browser.

---

**⚠️ The trap — and it's the single most common Spring Security + Thymeleaf mistake in real codebases:** `sec:authorize` decides what *renders*. It has **zero** connection to what's actually *reachable*. Someone without `ROLE_ADMIN` never sees the "Admin Panel" link — but if the real server-side rule protecting `/admin` (your `.hasRole("ADMIN")` from Topic 2.9) is ever accidentally removed, weakened, or simply never written, that same person can still type the URL directly and get in. Hiding a link is a UX decision. `authorizeHttpRequests` is the security decision. They are backed by the same expression language, which makes them *feel* like the same mechanism — they are not.

**Closing the loop — the safer alternative:** `sec:authorize-url="/admin"` doesn't hardcode a role expression in the template at all. It asks the actual configured authorization rule for that URL+method whether the current user could reach it. If the real rule in `SecurityConfig` ever changes, this stays correct automatically — there's no second copy of the logic to drift out of sync. This is the exact same "one source of truth beats two copies that can disagree" principle Topic 2.1's `.permitAll()` was built around, applied here to display logic instead of routing.

| Real-world question | Mechanism |
|---|---|
| What actually triggers auto CSRF injection? | `th:action` → `RequestDataValueProcessor` SPI → `CsrfRequestDataValueProcessor` — **not** the `sec:` dialect |
| Does a plain `action="..."` form still get it? | No — the trigger is specifically the `th:action` processor |
| How does a template know who's logged in with no controller code? | `sec:authentication="expression"` — reads `Authentication` directly |
| Does hiding a link with `sec:authorize` protect the endpoint? | No — display only. Real enforcement is `authorizeHttpRequests` (2.9), completely separate |
| How to avoid the display rule drifting from the real rule? | `sec:authorize-url="/path"` — asks the actual configured rule, not a hardcoded copy |

---

## Part B — Lab

**Modules touched:** `credentials/`, `templates/`

### API surface covered this topic

| API | Purpose |
|---|---|
| `th:action` (Thymeleaf Spring dialect) | Triggers `RequestDataValueProcessor` on `<form>` rendering |
| `RequestDataValueProcessor` (Spring MVC SPI) | Generic hook; Spring Security's implementation supplies CSRF fields through it |
| `CsrfRequestDataValueProcessor` | Auto-configured bean that actually returns the hidden `_csrf` field |
| `xmlns:sec="http://www.thymeleaf.org/extras/spring-security"` | Namespace enabling the `sec:` dialect |
| `sec:authentication="name"` / `"principal.authorities"` | Reads properties off the current `Authentication`/`UserDetails` directly |
| `sec:authorize="expression"` | Strips an element from the DOM based on a security SpEL expression — display only |
| `sec:authorize-url="/path"` | Same display decision, sourced from the real configured authorization rule |

### `src/main/java/com/labs/formauth/credentials/LabUserDetailsService.java` (modified)
```java
package com.labs.formauth.credentials;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class LabUserDetailsService {

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails alice = User.withUsername("alice")
                .password(passwordEncoder.encode("password123"))
                .roles("USER")
                .build();

        UserDetails bob = User.withUsername("bob")
                .password(passwordEncoder.encode("password123"))
                .roles("USER")
                .accountLocked(true)
                .build();

        UserDetails carol = User.withUsername("carol")
                .password(passwordEncoder.encode("password123"))
                .roles("USER")
                .credentialsExpired(true)
                .build();

        // Added in 2.11: an actual ROLE_ADMIN user, so sec:authorize has
        // something real to differ on - alice and dave will render home.html
        // differently, from the identical template.
        UserDetails dave = User.withUsername("dave")
                .password(passwordEncoder.encode("password123"))
                .roles("USER", "ADMIN")
                .build();

        return new InMemoryUserDetailsManager(alice, bob, carol, dave);
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

<!--
  th:action (not plain action=) is what triggers auto CSRF injection - see
  Part A. The manual <input type="hidden" .../> from Topic 2.10 is GONE;
  this replaces it, it doesn't sit alongside it.
-->
<form th:action="@{/perform_login}" method="post">
    <label>Username: <input type="text" name="user"/></label><br/>
    <label>Password: <input type="password" name="pass"/></label><br/>
    <button type="submit">Log in</button>
</form>
</body>
</html>
```

### `src/main/resources/templates/home.html` (modified)
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org"
      xmlns:sec="http://www.thymeleaf.org/extras/spring-security">
<head><title>Form Auth Lab</title></head>
<body>
    <h1>You are logged in.</h1>

    <!-- No controller code produced these - read directly from the
         SecurityContext by the sec: dialect. -->
    <p>Signed in as: <span sec:authentication="name">?</span></p>
    <p>Authorities: <span sec:authentication="principal.authorities">?</span></p>

    <p><a href="/profile">Go to profile</a> | <a href="/logout">Logout</a></p>

    <!--
      DISPLAY ONLY - see Part A's trap. This <p> is entirely absent from
      the rendered HTML for anyone without ROLE_ADMIN, but that absence
      has zero effect on whether GET /admin actually succeeds for them.
      The real enforcement is SecurityConfig's .hasRole("ADMIN") (Topic 2.9).
    -->
    <p sec:authorize="hasRole('ADMIN')">
        <a href="/admin">Go to admin panel</a>
    </p>

    <!--
      Reuses the REAL configured rule for this exact URL instead of a
      second, hand-copied role expression that could drift out of sync.
    -->
    <p sec:authorize-url="/admin">
        (sec:authorize-url agrees: you can reach /admin)
    </p>
</body>
</html>
```

### Run it

```
mvn spring-boot:run
```

**Confirm the auto-injected field, at the raw HTTP level:**
```
curl http://localhost:8081/login | grep -A1 '<form'
```
**Expected:**
```html
<form action="/perform_login" method="post"><input type="hidden" name="_csrf" value="a1b2c3d4-..."/>
    <label>Username: ...
```
Note the field sits immediately after the opening `<form>` tag — that's `SpringActionTagProcessor`'s documented insertion point, not something you wrote.

**Log in as alice, view the rendered home page:**
```
curl -c cookies.txt -X POST http://localhost:8081/perform_login \
  -d "user=alice&pass=password123&_csrf=$(curl -s http://localhost:8081/login | grep -oP '(?<=name=\"_csrf\" value=\")[^\"]*')" -v
curl -b cookies.txt http://localhost:8081/
```
**Expected in the output:** `Signed in as: alice`, `Authorities: [ROLE_USER]` — and **no trace at all** of the "Go to admin panel" `<p>` or the `sec:authorize-url` line, anywhere in the HTML. Not commented out, not `display:none` — genuinely never emitted.

**Log in as dave (ROLE_ADMIN) instead** and repeat:
```
curl -b cookies.txt http://localhost:8081/
```
**Expected:** both admin-related `<p>` blocks now appear in full, including a real, clickable `<a href="/admin">`.

### Contrast experiment — proving `sec:authorize` alone protects nothing

Temporarily remove the real rule from `SecurityConfig.java`:
```java
.authorizeHttpRequests(auth -> auth
    .requestMatchers("/debug/**", "/403").permitAll()
    // .requestMatchers("/admin").hasRole("ADMIN")   <-- commented out
    .anyRequest().authenticated()
)
```
Restart, log back in as **alice** (still `ROLE_USER` only), and check both things:
```
curl -b cookies.txt http://localhost:8081/          # the template
curl -b cookies.txt http://localhost:8081/admin -v  # the actual endpoint
```
**Expected — and this is the whole point:** the home page still correctly *hides* the admin link for alice (`sec:authorize="hasRole('ADMIN')"` still evaluates `false` — nothing about the template changed). But `curl .../admin` now returns **`200`**, not `403`. The link being hidden told alice nothing false, but it also told her nothing true — the real protection was gone, and the template had no way to know that.

Now look at the `sec:authorize-url` line specifically, in that same broken state — it will have **flipped to visible** for alice, because it isn't a hardcoded copy of the rule; it asks the real (now-weakened) rule directly and gets an honest answer. Restore the `.hasRole("ADMIN")` line once you've confirmed this.

### Try it yourself

1. Revert `login.html`'s `<form th:action="@{/perform_login}">` back to plain `action="/perform_login"`. Rerun the `curl .../login | grep` command from above — confirm the hidden `_csrf` field disappears completely, tying this directly back to Topic 2.10's manual workaround.
2. Add a new line to `home.html`: `<p sec:authorize="isAuthenticated()">You're logged in, whoever you are.</p>`. Log in as alice, then as bob (if you can — remember bob is locked), then as dave — confirm this one renders for *any* successfully authenticated user, regardless of role, unlike the `hasRole('ADMIN')` block.
3. Change `sec:authentication="principal.authorities"` to `sec:authentication="credentials"` in `home.html` and reload as alice. What renders — the real password, or nothing at all? This connects directly back to Topic 2.3's `eraseCredentialsAfterAuthentication`: the `Authentication` object sitting in this exact request's `SecurityContext` had its credentials nulled out right after login succeeded, and the template is reading that same object live.

### Delta

**Modified:** `credentials/LabUserDetailsService.java` (added `dave`, `ROLE_ADMIN`), `templates/login.html` (`th:action` replaces manual CSRF field), `templates/home.html` (`sec:authentication`, `sec:authorize`, `sec:authorize-url`)