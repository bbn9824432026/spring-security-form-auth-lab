# Topic 2.3 — `AuthenticationManager` / `ProviderManager` / `AuthenticationProvider` chain

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** In 2.2 we stopped at one line: `getAuthenticationManager().authenticate(authRequest)`. From the filter's point of view, that's a black box — hand in an unverified token, get back either a verified one or an exception. But nothing about "verify a username and password" is inherently a single-step operation. A real system might need to check a local database *and* an LDAP directory *and* a break-glass emergency account — and it needs to try them in a defined order without any one of those mechanisms knowing the others exist.

**☕ API Mapping:** `AuthenticationManager` is the interface with exactly one method — `authenticate(Authentication)`. Spring Boot's autoconfiguration gives you a concrete implementation of it called `ProviderManager`. `ProviderManager` doesn't verify anything itself. It's a coordinator holding a `List<AuthenticationProvider>`, and its entire job is deciding which provider in that list gets a turn.

**⚠️ What was unmanageable before this separation existed:** without a pluggable list, adding a second credential source (say, LDAP, six months after launch) meant reopening the one function that already handled database login and special-casing it — `if (isLdapUser) { ... } else { checkDatabase(...) }`. Every new source coupled itself to every existing one. A bug in the new LDAP branch could break login for people who were never touching LDAP at all. `ProviderManager` exists specifically so each source is a self-contained object that only has to answer one question: "can you handle this kind of credential, yes or no?"

---

**🌍 Real World:** For each provider in its list, `ProviderManager` asks a yes/no question — "does this provider even know what to do with a `UsernamePasswordAuthenticationToken`?" — before spending any real effort on it. If yes, it calls that provider's `authenticate(...)` and looks at what comes back.

**☕ API Mapping:** That yes/no question is `AuthenticationProvider.supports(Class<?>)`. `DaoAuthenticationProvider` — the one auto-registered for you right now — returns `true` for `UsernamePasswordAuthenticationToken.class` and nothing else. This is exactly what gets auto-registered when Spring Boot's `AuthenticationConfiguration` notices you have a `UserDetailsService` bean and a `PasswordEncoder` bean and *no* `AuthenticationProvider` or `AuthenticationManager` bean of your own — it builds one for you, silently, using those two beans. That's the "auto-registered" part of this topic's title, and it's exactly what's been running invisibly since Topic 2.1.

**Deeper mechanism, one layer down — what `DaoAuthenticationProvider.authenticate()` actually does, in order:**
1. `retrieveUser(username)` → calls your `UserDetailsService.loadUserByUsername(username)`.
2. **Pre-authentication checks** run *before* the password is even looked at: `isAccountNonLocked()`, `isEnabled()`, `isAccountNonExpired()`. If any fail, it throws immediately — `LockedException`, `DisabledException`, `AccountExpiredException`.
3. `additionalAuthenticationChecks(...)` — the actual `PasswordEncoder.matches(raw, encoded)` call (2.5's subject; treated as opaque here).
4. **Post-authentication checks** run *after* the password matches: specifically `isCredentialsNonExpired()`.

**⚠️ The trap, part 1 (why the check order matters):** credential expiry is checked *after* the password, not before. This is deliberate — if it ran first, an attacker could probe usernames and learn "this account's password has expired" without ever proving they know the current password, which leaks account state to someone who hasn't authenticated at all. The ordering itself is a security decision, not an implementation accident.

---

**🌍 Real World:** Now imagine two providers both return `true` from `supports()`. What happens when the first one fails?

**☕ API Mapping:** Depends entirely on *what kind* of exception it throws:
- A generic `AuthenticationException` (like `BadCredentialsException`) → `ProviderManager` remembers it as `lastException` and tries the **next** provider.
- An `AccountStatusException` or `InternalAuthenticationServiceException` → rethrown **immediately**. No other provider gets a turn at all.
- Returning `null` (not throwing) → treated as "this provider abstains," silently moves to the next one.
- Returning a real `Authentication` → success, loop stops right there.

**⚠️ The trap, part 2 (the one this lab will reproduce):** if provider A throws `BadCredentialsException` and, further down the list, provider B *also* throws its own `BadCredentialsException` for a completely different reason, only **B's** message survives — it overwrites `lastException`. The person configuring the failure handler (2.7) sees B's message, even though A was the provider that actually applied to that user. This is a real, reported class of bug in multi-provider setups, not a theoretical one.

---

**🌍 Real World:** Once *something* succeeds, one more thing happens before the filter ever sees the result.

**☕ API Mapping:** `ProviderManager.eraseCredentialsAfterAuthentication` defaults to `true`. If the returned `Authentication` implements `CredentialsContainer` (which `UsernamePasswordAuthenticationToken` does), its `eraseCredentials()` method is called — the raw password field is nulled out, permanently, before the token goes anywhere else in the chain.

**⚠️ The trap, part 3:** if you ever write a success handler (2.6) expecting to read `authentication.getCredentials()` to get the raw password the user typed — say, to re-authenticate against a second downstream system with the same credentials — it will be `null`. Not empty, not the encoded hash. `null`. This surprises people constantly and it's by design: there's no legitimate reason for the plaintext password to still be sitting in memory once it's served its purpose.

**How to observe all of this directly:** DEBUG logging (already on) prints which provider `ProviderManager` is trying and the exact exception class each one throws. The lab below goes one step further and prints the object state at each stage explicitly, so you see the overwritten exception and the nulled-out credentials with your own eyes rather than trusting the description.

| Real-world step | Mechanism |
|---|---|
| "Can you even handle this token type?" | `AuthenticationProvider.supports(Class<?>)` |
| Which provider gets auto-wired with zero config | `DaoAuthenticationProvider`, built from your `UserDetailsService` + `PasswordEncoder` beans |
| Order of checks inside that provider | pre-checks (locked/disabled/expired) → password match → post-check (credentials expired) |
| A recoverable failure vs. a fatal one | generic `AuthenticationException` (try next) vs. `AccountStatusException`/`InternalAuthenticationServiceException` (stop immediately) |
| What happens to the password after success | `eraseCredentialsAfterAuthentication` nulls it via `CredentialsContainer.eraseCredentials()` |

---

## Part B — Lab

**Modules touched:** `authentication/` (extends what 2.2 started)

### API surface covered this topic

| API | Purpose |
|---|---|
| `AuthenticationManager.authenticate(Authentication)` | The single method every filter calls; implemented by `ProviderManager` |
| `ProviderManager(List<AuthenticationProvider>)` | Constructs the chain explicitly |
| `AuthenticationProvider.supports(Class<?>)` | Type-based dispatch gate |
| `AuthenticationProvider.authenticate(Authentication)` | Returns a verified token, `null` (abstain), or throws |
| `new DaoAuthenticationProvider(UserDetailsService)` + `.setPasswordEncoder(...)` | Explicit construction of what's normally auto-registered |
| `AbstractUserDetailsAuthenticationProvider` pre/post checks | Account status validation surrounding the password check |
| `ProviderManager.setEraseCredentialsAfterAuthentication(boolean)` | Controls whether credentials are nulled after success |
| `HttpSecurity.authenticationManager(AuthenticationManager)` | Wires a custom manager into the filter chain |

### `src/main/java/com/labs/formauth/authentication/BackupCredentialsAuthenticationProvider.java`
```java
package com.labs.formauth.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

// A second, completely independent credential source - a hardcoded
// "break-glass" account with nothing to do with the UserDetailsService.
// Exists purely to make the provider CHAIN itself observable.
public class BackupCredentialsAuthenticationProvider implements AuthenticationProvider {

    private static final String BREAK_GLASS_USER = "breakglass";
    private static final String BREAK_GLASS_PASS = "emergency123";

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        if (!BREAK_GLASS_USER.equals(username)) {
            // Not our account - ABSTAIN. Returning null tells ProviderManager
            // "not my concern, ask the next provider." This is the quiet path.
            System.out.println("[2.3] BackupProvider: '" + username + "' is not mine, abstaining (returning null)");
            return null;
        }

        if (!BREAK_GLASS_PASS.equals(password)) {
            // It WAS our username, but wrong password - this is a real failure,
            // not an abstain. Throwing here (not returning null) is what lets
            // this provider's exception potentially overwrite an earlier one.
            System.out.println("[2.3] BackupProvider: wrong break-glass password");
            throw new BadCredentialsException("Not a recognized break-glass account");
        }

        System.out.println("[2.3] BackupProvider: break-glass login succeeded");
        return UsernamePasswordAuthenticationToken.authenticated(
                username, password, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
```

### `src/main/java/com/labs/formauth/authentication/AuthenticationManagerConfig.java`
```java
package com.labs.formauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

// What Topic 2.1/2.2 were relying on invisibly, made explicit and controllable.
@Configuration
public class AuthenticationManagerConfig {

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService,
                                                                PasswordEncoder passwordEncoder) {
        // Constructor form - this IS what Boot was building for you silently.
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(DaoAuthenticationProvider daoAuthenticationProvider,
                                                         BackupCredentialsAuthenticationProvider backupProvider) {
        // ORDER MATTERS - see the contrast experiment below.
        // Dao first, then Backup: matches how you'd normally rank "real" users
        // above emergency access.
        ProviderManager manager = new ProviderManager(List.of(daoAuthenticationProvider, backupProvider));

        // Explicit, even though true is the default - stated so it's visible,
        // not hidden behind a default you'd have to know to look for.
        manager.setEraseCredentialsAfterAuthentication(true);
        return manager;
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

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            // Wires OUR explicit ProviderManager (2.3) in place of the one
            // Spring Boot would otherwise build invisibly. Everything below
            // this point is unchanged from Topic 2.1.
            .authenticationManager(authenticationManager)
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/perform_login")
                .usernameParameter("user")
                .passwordParameter("pass")
                .defaultSuccessUrl("/", false)
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

**Case 1 — the real user:**
```
curl -X POST http://localhost:8081/perform_login -d "user=alice&pass=password123" -v
```
Console:
```
[2.3] BackupProvider: 'alice' is not mine, abstaining (returning null)
```
Wait — that's *not* what you'll see first. `ProviderManager` tries providers **in list order**: `Dao` first. Dao succeeds outright for alice, so `ProviderManager` breaks the loop before `Backup` ever runs. Expected console output is actually just the DEBUG lines from `DaoAuthenticationProvider` (no `[2.3]` print at all — `BackupCredentialsAuthenticationProvider` never got a turn, because Dao returned non-null first). `302 Location: /`.

**Case 2 — the break-glass account:**
```
curl -X POST http://localhost:8081/perform_login -d "user=breakglass&pass=emergency123" -v
```
Console:
```
[2.3] BackupProvider: break-glass login succeeded
```
Here Dao *did* run first — it called `retrieveUser("breakglass")`, got `UsernameNotFoundException` (translated internally to `BadCredentialsException`, stored as `lastException`), then `ProviderManager` moved on to Backup, which succeeded. `302 Location: /`.

### Contrast experiment — the overwritten-exception trap, reproduced exactly

```
curl -X POST http://localhost:8081/perform_login -d "user=alice&pass=WRONGPASSWORD" -v
```
Trace it through:
1. `Dao` provider: finds `alice`, password doesn't match → throws `BadCredentialsException("Bad credentials")`. `ProviderManager` stores it as `lastException`, moves on.
2. `Backup` provider: `"alice" != "breakglass"` → **but look at the code above — this provider throws for wrong password, not for wrong username.** Since the username check fails first, it returns `null` (abstains) here, so it does *not* overwrite anything this time.
3. Final exception thrown to the failure handler is Dao's — correct, because nothing else actually competed.

Now flip it to see the actual overwrite: temporarily change `BackupCredentialsAuthenticationProvider` so it throws instead of abstaining on username mismatch:
```java
if (!BREAK_GLASS_USER.equals(username)) {
    throw new BadCredentialsException("Unknown account in backup store");   // was: return null
}
```
Rerun the same curl command. **Now** the final exception the failure handler receives is `"Unknown account in backup store"` — Backup's message, silently replacing Dao's genuinely-relevant `"Bad credentials"`. Same wrong password, completely different (and misleading) error message, purely because of provider order and how each one chose to fail. Revert the change once you've seen it.

### Try it yourself

1. Swap the list order in `AuthenticationManagerConfig` to `List.of(backupProvider, daoAuthenticationProvider)`. Log in as `alice` again — check the console: does `[2.3] BackupProvider` print now, even though alice has nothing to do with the backup account? This isolates exactly when each provider gets a turn.
2. Set `manager.setEraseCredentialsAfterAuthentication(false)`. Add a temporary `System.out.println(authentication.getCredentials())` inside `InstrumentedUsernamePasswordAuthenticationFilter` (from 2.2) right after the `super.attemptAuthentication(...)` call. Compare the printed value with `true` vs `false` — you'll see the raw password survive when erasure is off, and `null` when it's on.
3. In `LabUserDetailsService`, temporarily change `alice`'s builder to add `.disabled(true)`. Attempt login with the *correct* password. Which exception type appears in the console — is it thrown before or after the password would have been checked? This confirms the pre-check-vs-post-check ordering from Part A.

### Delta

**Added:** `authentication/BackupCredentialsAuthenticationProvider.java`, `authentication/AuthenticationManagerConfig.java`
**Modified:** `config/SecurityConfig.java`