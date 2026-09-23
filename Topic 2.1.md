# Topic 2.1 — `formLogin()`: the DSL surface

## Part A — What's actually happening (process-first)

Let's build this up one physical step at a time. No API names yet — just what happens on the wire and in the browser.

---

**🌍 Real World:** Your browser sends `GET /profile`. It has no cookie, no header, nothing proving who's asking. The server's decision point looks at this request and concludes: *I don't know who this is, and this resource requires knowing who someone is.* At the HTTP level, a server only has two honest ways to respond to that: send back `401` with a `WWW-Authenticate` header (which makes the browser pop up its own native, unstylable login box — this is exactly what you saw when you ran the shell project a moment ago, before any custom config existed), or send back a `302` redirect pointing the browser somewhere else — a page *you* control.

Form login always chooses the second option.

**☕ API Mapping:** `.loginPage("/login")` is that "somewhere else." It's a plain string, and it becomes the literal value written into the `Location:` header of that 302 response. Spring Security has no idea what routes your app defines — this one line is the only reason it knows where to send someone.

**⚠️ The trap (part 1):** setting `loginPage()` alone doesn't make `/login` reachable. The same rule that says "everything needs authentication" also applies to `/login` itself. If you stop here, you get an infinite loop: unauthenticated request → redirected to `/login` → `/login` itself is unauthenticated → redirected to `/login` → forever. We'll reproduce this exactly in Part B.

---

**🌍 Real World:** The browser renders whatever HTML `/login` returns. A person types into two `<input>` fields and clicks submit. The browser now does something very mechanical: it takes those two values, URL-encodes them, and writes them as the *body* of an HTTP POST — bytes like `user=alice&pass=secret123` — then opens (or reuses) a TCP connection and sends that POST to one specific URL.

The servlet container receives those bytes and, because the `Content-Type` says `application/x-www-form-urlencoded`, parses them into a parameter map *before any of your code runs*. That parsing is just `HttpServletRequest.getParameter(key)` under the hood — a plain string lookup.

**☕ API Mapping:** `.loginProcessingUrl("/perform_login")` tells Spring Security exactly which URL+method combination to intercept — before the request ever reaches `DispatcherServlet` or any `@Controller`. `.usernameParameter("user")` and `.passwordParameter("pass")` tell it which two keys to pull out of that parsed map. Spring can't guess your `<input name="...">` values — your HTML is arbitrary, so this has to be told, not inferred.

*(The filter object that does this interception — what it's actually made of — is Topic 2.2. Right now, treat it as: "the DSL configures it; something intercepts the URL.")*

**⚠️ The trap (part 2):** if the string in `usernameParameter(...)` doesn't exactly match the `name=` attribute in your HTML, `getParameter("user")` silently returns `null`. You won't get an exception — you'll get "Bad credentials" every single time, even with the right password, because the filter never even saw a username to check. This is one of the most common "why doesn't my login work" bugs, and it's purely a string-matching mismatch, not a security failure.

---

**🌍 Real World:** After validation happens (2.3's subject), the server is still just sitting there needing to send *some* HTTP response to that POST. There are exactly two branches: success needs a `Set-Cookie` header (a fresh authenticated session) plus a redirect somewhere; failure needs a redirect somewhere else, with no cookie.

**☕ API Mapping:** `.defaultSuccessUrl("/", false)` — the second argument matters more than it looks. `false` means: *if the person was redirected here because they tried to visit a specific deep link, send them back to that link instead of always dumping them on `/`.* `.failureUrl("/login?error")` is the other branch's destination.

**⚠️ The trap (part 3):** if you set `alwaysUse=true` (or omit the boolean, which is *not* the same as `false` — omitting it defaults success handling differently), every login lands on the same fixed page, even when someone specifically tried to open `/profile` before being challenged. This is the "why does my app always dump users on the homepage" complaint you'll see in real bug trackers.

---

**🌍 Real World:** Back to the loop problem from step one. The filter chain needs a way to say "authenticate everything, *except* the handful of URLs whose entire job is granting authentication in the first place."

**☕ API Mapping:** `.permitAll()`, called directly on the `formLogin(...)` configurer (not on your authorization rules), automatically adds `loginPage`, `loginProcessingUrl`, and `failureUrl` to the permitted list. One call, three URLs, always in sync — instead of you hand-listing the same three strings twice in two different places and having them drift apart later.

---

**Closing the loop:** everything above is *declarative configuration* — you're not writing a filter, you're filling in a builder (`FormLoginConfigurer`) with values. When `http.build()` runs, Spring Security uses those values to construct and register a real filter object into the same `VirtualFilterChain` you already met in your Group 1 work on `FilterChainProxy` — same mechanism, new filter. What that filter object actually does internally is Topic 2.2.

**How to observe this yourself, not just trust it:** `application.yml` already has `logging.level.org.springframework.security=DEBUG` set from the project shell. Watch the console during a login attempt — you'll see explicit lines naming which handler class fired (e.g. an authentication-success handler class, a redirect target) and *why* a request was or wasn't permitted. Also open your browser's Network tab with "preserve log" on: you'll physically see the `302` → `/login`, the `POST /perform_login`, and the final `302` with `Set-Cookie`, in order.

| Real-world step | API element |
|---|---|
| Unauthenticated request needs somewhere to redirect to | `.loginPage(url)` |
| Browser's POST needs an exact interception target | `.loginProcessingUrl(url)` |
| Filter needs to know which form field keys to read | `.usernameParameter()` / `.passwordParameter()` |
| Success needs a redirect target (respecting deep links) | `.defaultSuccessUrl(url, alwaysUse)` |
| Failure needs a different redirect target | `.failureUrl(url)` |
| Login-related URLs must escape "authenticate everything" | `.permitAll()` on the formLogin configurer |

---

## Part B — Lab

**Modules touched:** `config/`, `credentials/` (minimal scaffold, expanded in 2.4/2.5), `web/`, `templates/`

### API surface covered this topic

| API | Purpose |
|---|---|
| `HttpSecurity.formLogin(Customizer<FormLoginConfigurer<HttpSecurity>>)` | Entry point into the form-login DSL |
| `.loginPage(String)` | URL the unauthenticated-challenge redirect points to |
| `.loginProcessingUrl(String)` | URL+POST the auth filter intercepts |
| `.usernameParameter(String)` / `.passwordParameter(String)` | Form field names the filter reads |
| `.defaultSuccessUrl(String, boolean)` | Redirect target on success; boolean controls deep-link override |
| `.failureUrl(String)` | Redirect target on failed authentication |
| `.permitAll()` (on the formLogin configurer) | Auto-permits loginPage/loginProcessingUrl/failureUrl |
| `HttpSecurity.authorizeHttpRequests(...)` | Minimal scaffold here (`anyRequest().authenticated()`) — full matcher semantics are Group 3 territory, not this topic |
| `HttpSecurity.csrf(csrf -> csrf.disable())` | Temporarily off — see note below, revisited properly in 2.10 |

### `src/main/java/com/labs/formauth/credentials/PasswordEncoderConfig.java`
```java
package com.labs.formauth.credentials;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

// Minimal scaffold only. Full treatment (encoding IDs, BCrypt internals,
// why DelegatingPasswordEncoder exists) is Topic 2.5. This bean exists
// here only so something can encode/check the demo password below.
@Configuration
public class PasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
```

### `src/main/java/com/labs/formauth/credentials/LabUserDetailsService.java`
```java
package com.labs.formauth.credentials;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

// Minimal scaffold only. Full UserDetailsService/UserDetails contract
// is Topic 2.4. One static, hardcoded user — no DAO layer.
@Configuration
public class LabUserDetailsService {

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails alice = User.withUsername("alice")
                .password(passwordEncoder.encode("password123"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(alice);
    }
}
```

### `src/main/java/com/labs/formauth/config/SecurityConfig.java`
```java
package com.labs.formauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Scaffolding only — matcher-based rules are Group 3's subject.
            // For this lab: no session, no access, period.
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                // Part A step 1: the 302 challenge needs a Location header value.
                .loginPage("/login")

                // Part A step 2: exact URL+method the auth filter listens on.
                .loginProcessingUrl("/perform_login")

                // Part A step 2: which parsed form-body keys to read.
                .usernameParameter("user")
                .passwordParameter("pass")

                // Part A step 3: success redirect. false = prefer a saved
                // deep link over this fixed URL when one exists.
                .defaultSuccessUrl("/", false)

                // Part A step 3: failure redirect.
                .failureUrl("/login?error")

                // Part A step 4 (the trap): without this, anyRequest()
                // .authenticated() above blocks /login itself -> infinite
                // redirect loop. This keeps all three URLs in sync automatically.
                .permitAll()
            )
            // TEMPORARY. login.html has no CSRF token yet. Topic 2.10 explains
            // CsrfFilter properly and turns this back on with the Thymeleaf
            // sec: dialect. Leaving CSRF on right now would 403 every POST
            // to /perform_login before it even reached the auth filter.
            .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
```

### `src/main/java/com/labs/formauth/web/LoginController.java`
```java
package com.labs.formauth.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    // Spring Security's LoginUrlAuthenticationEntryPoint only guarantees the
    // redirect. It does NOT generate a page for a custom loginPage() — you
    // own the rendering, which is why this mapping has to exist at all.
    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }
}
```

### `src/main/java/com/labs/formauth/web/ProfileController.java`
```java
package com.labs.formauth.web;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

// A second protected route — exists only so you have a real deep link
// to test defaultSuccessUrl's alwaysUse flag against (Try It #1 below).
@Controller
public class ProfileController {

    @GetMapping("/profile")
    public String profile(Authentication authentication, Model model) {
        model.addAttribute("username", authentication.getName());
        return "profile";
    }
}
```

### `src/main/resources/templates/login.html`
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Login</title></head>
<body>
<h1>Log in</h1>

<!-- ?error is added to the URL by failureUrl above -->
<p th:if="${param.error}" style="color:red;">Invalid username or password.</p>

<form action="/perform_login" method="post">
    <!--
      action must exactly match loginProcessingUrl in SecurityConfig.
      No CSRF hidden field yet on purpose — see the .csrf(disable) note.
    -->
    <label>Username: <input type="text" name="user"/></label><br/>
    <!-- name="user" must exactly match usernameParameter("user") -->
    <label>Password: <input type="password" name="pass"/></label><br/>
    <!-- name="pass" must exactly match passwordParameter("pass") -->
    <button type="submit">Log in</button>
</form>
</body>
</html>
```

### `src/main/resources/templates/profile.html`
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Profile</title></head>
<body>
    <h1>Profile page</h1>
    <p>Logged in as: <span th:text="${username}">?</span></p>
    <p><a href="/">Home</a> | <a href="/logout">Logout</a></p>
    <!--
      /logout already works even though we never called .logout() ourselves —
      Spring Security registers a default logout mapping automatically.
      Full mechanics are Topic 2.12.
    -->
</body>
</html>
```

### `src/main/resources/templates/home.html` (modified)
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Form Auth Lab</title></head>
<body>
    <h1>You are logged in.</h1>
    <p><a href="/profile">Go to profile</a> | <a href="/logout">Logout</a></p>
</body>
</html>
```

---

### Run it

```
mvn spring-boot:run
```

Open an **incognito window** at `http://localhost:8081/profile`.

**Expected, step by step:**
1. `GET /profile` → immediate `302` to `/login` — your custom form, not a browser popup. This is Part A step 1.
2. Submit `alice` / `password123`.
3. `POST /perform_login` → `302` to **`/profile`**, not `/`. This confirms `defaultSuccessUrl("/", false)` actually preferred your original deep link over the fixed default — you can see the redirect chain in the Network tab.
4. Console (DEBUG on) shows the filter chain naming which handler ran and where it redirected — this is your direct proof, not a claim.

### Contrast experiment — reproduce the trap

In `SecurityConfig.java`, comment out `.permitAll()`:

```java
.formLogin(form -> form
    .loginPage("/login")
    .loginProcessingUrl("/perform_login")
    .usernameParameter("user")
    .passwordParameter("pass")
    .defaultSuccessUrl("/", false)
    .failureUrl("/login?error")
    // .permitAll()   <-- commented out
)
```

Restart, hit `/` in a fresh incognito window. **Expected:** your browser reports `ERR_TOO_MANY_REDIRECTS` (or Firefox's equivalent). `/login` is now itself behind `anyRequest().authenticated()`, so the entry point redirects to `/login`, which redirects to `/login`, forever. Uncomment `.permitAll()` and restart to confirm it resolves immediately.

### Try it yourself

1. Change `.defaultSuccessUrl("/", false)` to `.defaultSuccessUrl("/", true)`. Restart, hit `/profile` while logged out, log in — you'll now land on `/` instead of `/profile`, even though `/profile` is exactly what you asked for. This isolates Part A's "alwaysUse eats deep links" claim.
2. Change `.usernameParameter("user")` to `.usernameParameter("username")` but leave `login.html`'s `name="user"` untouched. Log in with correct credentials — you'll get "Invalid username or password" every time. Check DEBUG logs: `getParameter("username")` is returning `null` because the field is actually named `user`. This isolates the parameter-mismatch trap.
3. Delete the `.permitAll()` line (contrast experiment above), but this time also delete `.loginPage("/login")` entirely so Spring Security falls back to its own generated login page. Observe: no redirect loop this time — Spring's own generated login endpoint is auto-permitted internally, which tells you the loop was specifically about *your custom* `/login` never being added to the permit list, not about form login in general.

### Delta

**Added:** `config/SecurityConfig.java`, `credentials/PasswordEncoderConfig.java`, `credentials/LabUserDetailsService.java`, `web/LoginController.java`, `web/ProfileController.java`, `templates/login.html`, `templates/profile.html`
**Modified:** `templates/home.html`