# Topic 2.4 — `UserDetailsService` & `UserDetails` contract

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** Back in 2.3, `DaoAuthenticationProvider.retrieveUser(username)` needed to answer one question: "does a user with this name exist, and if so, what does their record actually contain?" That question has to be answerable regardless of whether the answer lives in a database row, an LDAP entry, a config file, or — like right now — a hardcoded value sitting in memory. The provider can't care which one it is.

**☕ API Mapping:** `UserDetailsService` is the entire boundary that makes that possible. It's one method: `loadUserByUsername(String) -> UserDetails`, with exactly two allowed outcomes — return a populated object, or throw `UsernameNotFoundException`. Nothing else. That's the whole contract.

**⚠️ What was unmanageable before this boundary existed:** without a dedicated interface sitting between "verify credentials" and "where credentials live," authentication code used to be written straight against one storage mechanism — a raw JDBC query inline in the login check, say. Moving from a properties file to a database, or a database to LDAP, meant rewriting the authentication logic itself, not swapping one lookup function. `UserDetailsService` is deliberately *just* a lookup — it has no idea `DaoAuthenticationProvider` exists, and `DaoAuthenticationProvider` has no idea whether the answer came from a `Map`, a `ResultSet`, or a network call.

---

**🌍 Real World:** Once a record is found, `DaoAuthenticationProvider` needs more than just a password to compare — it needs to know: is this account even allowed to log in right now? Locked? Disabled? Expired? These are yes/no facts about account *state*, separate from whether the password is correct.

**☕ API Mapping:** `UserDetails` is a passive data holder — seven methods, no logic: `getUsername()`, `getPassword()`, `getAuthorities()`, and four booleans — `isAccountNonExpired()`, `isAccountNonLocked()`, `isCredentialsNonExpired()`, `isEnabled()`. These four booleans are exactly what 2.3's pre/post-authentication checks called directly. This topic is where that data actually gets populated, instead of being assumed.

**Deeper mechanism — authorities:** `getAuthorities()` returns a collection of `GrantedAuthority`, a single-method interface (`getAuthority(): String`). `SimpleGrantedAuthority` is just a wrapper around a plain string like `"ROLE_USER"`. Nothing in the interface enforces the `"ROLE_"` prefix — that's purely a Spring Security convention that later authorization checks (Group 3 territory) rely on. Worth knowing now because it's the exact string this topic's builder produces.

---

**🌍 Real World:** What happens if `loadUserByUsername("mallory")` finds nothing, versus finding "alice" but the wrong password? From an attacker's perspective, those are two very different, very useful pieces of information — "that username doesn't exist" tells them to try a different one.

**☕ API Mapping:** `UsernameNotFoundException` is its own distinct exception type specifically so it *could* be told apart from `BadCredentialsException` — but `AbstractUserDetailsAuthenticationProvider.hideUserNotFoundExceptions` defaults to `true`, meaning `DaoAuthenticationProvider` deliberately catches it and rethrows a generic `BadCredentialsException` instead. The distinct exception type exists for *your* code to catch during development or logging — but by the time it reaches the failure handler (2.7), unknown-user and wrong-password look identical on purpose.

**⚠️ The trap, part 1:** flipping `hideUserNotFoundExceptions` to `false` (there are tutorials that suggest this "for clearer error messages") turns your login endpoint into a username enumeration tool. It's a genuinely useful debugging switch in a local dev profile and a real vulnerability in production.

---

**🌍 Real World:** After a successful login, your controller code (like `ProfileController` from 2.1) calls `authentication.getName()` and gets back a clean string, `"alice"`. It's easy to assume `authentication.getPrincipal()` is that same string. It isn't.

**☕ API Mapping:** `DaoAuthenticationProvider` has a property, `forcePrincipalAsString`, defaulting to **`false`**. That means the `Authentication` object's principal is, by default, the *entire `UserDetails` object* that `loadUserByUsername()` returned — not a `String`. `getName()` only *looks* like it returns a plain string because `AbstractAuthenticationToken.getName()` specifically checks "is my principal a `UserDetails`? If so, return its `getUsername()`." That convenience is hiding the real object underneath.

**⚠️ The trap, part 2 (the one this lab reproduces directly):** cast `authentication.getPrincipal()` to `String` anywhere in your code, and it compiles fine and blows up at runtime with a `ClassCastException` — but only in production traffic, since it depends entirely on what the actual authenticated request looked like. This is one of the most common real-world NPEs/CCEs in Spring Security codebases.

**How to observe this directly:** print `authentication.getPrincipal().getClass().getName()` from any authenticated request — Part B does exactly that, live, against your own running app.

| Real-world question | Mechanism |
|---|---|
| Where do credentials/status live, regardless of storage? | `UserDetailsService.loadUserByUsername(String)` |
| What does a "user record" actually contain? | `UserDetails` — 3 getters + 4 status booleans |
| What's a permission/role, structurally? | `GrantedAuthority.getAuthority()` → plain string |
| Unknown user vs. wrong password — told apart or not? | `UsernameNotFoundException`, masked by `hideUserNotFoundExceptions=true` |
| What is `authentication.getPrincipal()` really? | The full `UserDetails` object, not a `String`, unless `forcePrincipalAsString=true` |

---

## Part B — Lab

**Modules touched:** `credentials/`, `web/`

### API surface covered this topic

| API | Purpose |
|---|---|
| `UserDetailsService.loadUserByUsername(String)` | The one-method contract itself |
| `UserDetails` (interface) | 3 identity getters + 4 status booleans |
| `GrantedAuthority` / `SimpleGrantedAuthority` | Represents one authority as a plain string |
| `User.withUsername(...).password(...).roles(...).accountLocked(...).disabled(...).build()` | Fluent builder producing a concrete `UserDetails` |
| `InMemoryUserDetailsManager` | Convenience `UserDetailsService`, backed by an internal case-insensitive map |
| `UserDetailsManager` (`createUser`/`updateUser`/`deleteUser`/`userExists`/`changePassword`) | Extended, mutation-capable contract — only on managers, not the base interface |
| `UsernameNotFoundException` | Thrown on lookup failure; masked into `BadCredentialsException` by default |
| `DaoAuthenticationProvider.setForcePrincipalAsString(boolean)` | Controls whether the principal ends up as `UserDetails` or `String` |

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

        // Added in 2.4: a second account with a status flag actually SET,
        // so the pre-authentication checks from Topic 2.3 have something
        // real to reject instead of being taken on faith.
        UserDetails bob = User.withUsername("bob")
                .password(passwordEncoder.encode("password123"))
                .roles("USER")
                .accountLocked(true)   // isAccountNonLocked() will now return false
                .build();

        // InMemoryUserDetailsManager stores these in an internal map and,
        // notably, normalizes usernames to lowercase internally - see
        // Try It Yourself #2.
        return new InMemoryUserDetailsManager(alice, bob);
    }
}
```

### `src/main/java/com/labs/formauth/credentials/StaticUserStore.java` (new — toggle-only comparison)
```java
package com.labs.formauth.credentials;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * TOGGLE-ONLY. Not wired into Spring by default - LabUserDetailsService is
 * the active bean. This class exists solely to show the raw contract with
 * ZERO convenience classes: no InMemoryUserDetailsManager, just a Map and
 * two interfaces implemented by hand.
 *
 * To run this instead: comment out @Configuration on LabUserDetailsService,
 * uncomment it here. Only one UserDetailsService bean can exist at a time.
 */
// @Configuration
public class StaticUserStore implements UserDetailsService {

    // In a real hand-rolled store, this would be a pre-encoded hash pasted
    // in once, or fetched from wherever. The point: loadUserByUsername()
    // never encodes anything - it only ever returns what's already stored.
    private static final Map<String, RawUser> USERS = Map.of(
        "alice", new RawUser("alice", "{noop}password123", false, false),
        "bob",   new RawUser("bob",   "{noop}password123", true, false)
    );

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // This IS the entire contract. Exactly two outcomes are allowed:
        // a populated UserDetails, or this exception. Nothing else.
        RawUser found = USERS.get(username);
        if (found == null) {
            throw new UsernameNotFoundException("No such user: " + username);
        }
        return found.toUserDetails();
    }

    private record RawUser(String username, String encodedPassword, boolean locked, boolean disabled) {
        UserDetails toUserDetails() {
            return new UserDetails() {
                @Override public String getUsername() { return username; }
                @Override public String getPassword() { return encodedPassword; }
                @Override public Collection<? extends GrantedAuthority> getAuthorities() {
                    return List.of(new SimpleGrantedAuthority("ROLE_USER"));
                }
                @Override public boolean isAccountNonExpired() { return true; }
                @Override public boolean isAccountNonLocked() { return !locked; }
                @Override public boolean isCredentialsNonExpired() { return true; }
                @Override public boolean isEnabled() { return !disabled; }
            };
        }
    }
}
```

### `src/main/java/com/labs/formauth/web/ProfileController.java` (modified)
```java
package com.labs.formauth.web;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ProfileController {

    @GetMapping("/profile")
    public String profile(Authentication authentication, Model model) {
        model.addAttribute("username", authentication.getName());

        // Topic 2.4's central trap, made visible: getPrincipal() is NOT a
        // String by default - it's the full UserDetails object DaoAuthenticationProvider
        // retrieved and validated back in 2.3.
        Object principal = authentication.getPrincipal();
        System.out.println("[2.4] principal class -> " + principal.getClass().getName());
        System.out.println("[2.4] principal.toString() -> " + principal);
        // Uncomment to see it fail at runtime, not compile time:
        // String username = (String) principal;

        return "profile";
    }
}
```

### Run it

```
mvn spring-boot:run
```

Log in as `alice` / `password123`, then visit `/profile`. Console:
```
[2.4] principal class -> org.springframework.security.core.userdetails.User
[2.4] principal.toString() -> org.springframework.security.core.userdetails.User [Username=alice, Password=[PROTECTED], Enabled=true, ...]
```
Note it's `User` — the concrete class the builder produced — not `java.lang.String`. Uncomment the cast line and refresh `/profile`: `500` with a `ClassCastException` in the console, at exactly the line you uncommented.

**Locked account:** attempt to log in as `bob` / `password123`. Expected: redirected to `/login?error` — same as a wrong password, from the outside. Console (DEBUG) shows `LockedException` was thrown internally, but the person on the login page can't tell the difference. That's `hideUserNotFoundExceptions`-adjacent behavior in spirit: account-state detail is available to *you*, not to the requester. (2.7 is where you'll build a failure handler that *does* surface distinct messages for this — deliberately.)

### Contrast experiment

Toggle to `StaticUserStore` (comment out `LabUserDetailsService`'s `@Configuration`, uncomment it on `StaticUserStore`). Restart, log in as `alice` / `password123` — it still works, identically, from the outside. The entire authentication flow from 2.1 through 2.3 is completely unaware it's now talking to a hand-written `Map` lookup instead of `InMemoryUserDetailsManager`. That's the payoff of the interface boundary Part A described: nothing downstream had to change.

### Try it yourself

1. In `StaticUserStore`, change `"bob"`'s `locked` flag to `false` but set `disabled` to `true` instead. Toggle it active, attempt login as bob. Same outward behavior (redirect to error) — confirms both status flags are checked and both fail the same way from the requester's point of view.
2. With `LabUserDetailsService` active, attempt login with `user=ALICE&pass=password123` (uppercase username) via curl. It succeeds — `InMemoryUserDetailsManager` normalizes lookups to lowercase internally. Now toggle to `StaticUserStore` and try the same uppercase request — it fails, because the hand-written `Map.get("ALICE")` does no such normalization. Same interface, two different real-world behaviors, entirely dependent on the implementation.
3. Temporarily set `hideUserNotFoundExceptions` to `false` on the `DaoAuthenticationProvider` bean from `AuthenticationManagerConfig` (2.3) — add `daoAuthenticationProvider.setHideUserNotFoundExceptions(false);` in that `@Bean` method. Attempt login with a genuinely nonexistent username vs. a real username with the wrong password, and compare the DEBUG console output for each — you should now see the two failure modes producing visibly different exception types where before they looked identical.

### Delta

**Added:** `credentials/StaticUserStore.java`
**Modified:** `credentials/LabUserDetailsService.java` (added `bob`, a locked account), `web/ProfileController.java` (principal-type debug output)