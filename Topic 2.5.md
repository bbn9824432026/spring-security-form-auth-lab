# Topic 2.5 — `PasswordEncoder` & `DelegatingPasswordEncoder`

## Part A — What's actually happening (process-first)

---

**🌍 Real World:** `additionalAuthenticationChecks()` in `DaoAuthenticationProvider` (2.3) needs to compare a password the user just typed against something stored from before. It can never *decrypt* the stored value back into the original password — that's not how one-way hashing works, by design. What it can physically do is re-run the *same transformation* on the freshly-typed password and compare the two transformed outputs, byte for byte.

**☕ API Mapping:** That's the entire `PasswordEncoder` contract — two methods: `encode(CharSequence raw) -> String` and `matches(CharSequence raw, String encoded) -> boolean`. `matches()` never reverses anything; it re-derives and compares.

**⚠️ What broke before algorithms like this existed:** fast, unsalted hashes (plain MD5, SHA-1, or worse — plaintext columns) were routine in production systems for years. When databases leaked — Adobe in 2013, LinkedIn in 2012 are the textbook cases — attackers cracked huge fractions of the dumped hashes almost immediately, because a GPU can compute billions of MD5 hashes per second, and identical passwords produced identical hashes, so one precomputed rainbow table cracked every account sharing a password at once.

---

**🌍 Real World:** To defeat that, you need two properties: make each computation *deliberately slow* (so billions-per-second brute force becomes thousands-per-second), and make identical passwords produce *different* stored values (so no single precomputed table works against more than one account).

**☕ API Mapping:** BCrypt gets both from one mechanism. Every stored value looks like `$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy` — and every piece of that string is meaningful: `$2a$` is the algorithm version, `10` is the **cost factor** (literally 2^10 = 1024 internal rounds — raise it to 12 and you get 4× the rounds, 4× the wall-clock time, exactly), the next 22 characters are a randomly generated **salt**, and the rest is the actual hash output. The salt is generated fresh per password and stored right alongside the hash, in plain sight — that's fine, because the security doesn't depend on the salt being secret, only on making precomputation across accounts useless.

---

**🌍 Real World:** A real application's user table almost never has passwords stored under one single algorithm forever. Systems get inherited, algorithms get deprecated, migrations happen gradually — you can't force every user to log in on the same day to re-hash their password.

**☕ API Mapping:** `DelegatingPasswordEncoder` solves this by tagging every stored value with an id prefix: `{bcrypt}$2a$10$...`. `encode()` always uses whichever encoder is currently registered as the default and stamps its id on the front. `matches()` does the opposite — it reads the `{id}` off the *stored* value and looks up that *specific* decoder from an internal map, completely ignoring what today's default happens to be.

**⚠️ What was unmanageable before this existed:** pre-5.0 Spring Security configured one fixed `PasswordEncoder` for the whole app. Migrating from a legacy algorithm to bcrypt meant either a disruptive one-time mass re-hash (impossible — you don't have anyone's plaintext password anymore) or hand-rolled branching logic bolted onto the encoder itself. The `{id}` tag makes old and new hashes coexist in the same column indefinitely, each validated by the decoder that actually produced it.

---

**⚠️ The trap:** if a value in your store has *no* `{id}` prefix at all — because it was written by calling `BCryptPasswordEncoder` directly instead of going through `DelegatingPasswordEncoder`, or it's genuinely legacy data nobody tagged — `matches()` doesn't silently fall back to some default. It throws `IllegalArgumentException`. This is not a bug; it's `DelegatingPasswordEncoder` refusing to guess which algorithm applies to an ambiguous value, since guessing wrong here means silently accepting or rejecting a password incorrectly.

**Closing the loop / deeper mechanism:** the same `{id}` tag also drives `upgradeEncoding(String)`, which `DaoAuthenticationProvider` checks after a *successful* login. If the stored value's id doesn't match today's default, this returns `true` — the exact signal a production system uses to silently re-encode a user's password with the newer algorithm the next time they log in, without ever asking them to change anything. That's the real mechanism behind "gradually migrating everyone off an old hash algorithm."

**How to observe this directly:** everything above is a plain Java object with no HTTP involved — the sharpest way to see it is calling these methods directly and printing the actual strings, which is exactly what Part B does.

| Real-world need | Mechanism |
|---|---|
| Compare without ever reversing | `PasswordEncoder.encode()` / `.matches()` — always re-derive, never decrypt |
| Deliberately slow, so brute force doesn't scale | BCrypt cost factor = literally 2^n rounds |
| Same password, different stored values | Random per-password salt, embedded in the stored string itself |
| Multiple algorithms coexisting during migration | `{id}` prefix — `matches()` reads it, `encode()` always writes today's default |
| Unknown/missing id | `IllegalArgumentException` — refuses to guess |
| Silent algorithm migration on login | `upgradeEncoding(String)` + `UserDetailsPasswordService` (forward reference — not built in this lab) |

---

## Part B — Lab

**Modules touched:** `credentials/` (comment-only clarification of existing bean), new `src/test/java` tree

Password encoding is a pure object-level API with no HTTP request involved, so this lab is a JUnit test class you run directly — more precise and faster to iterate on than driving it through curl.

### API surface covered this topic

| API | Purpose |
|---|---|
| `PasswordEncoder.encode(CharSequence)` / `.matches(CharSequence, String)` | The two-method contract |
| `BCryptPasswordEncoder()` / `BCryptPasswordEncoder(int strength)` | Concrete algorithm; `strength` is the cost factor (rounds = 2^strength) |
| `PasswordEncoderFactories.createDelegatingPasswordEncoder()` | Builds the recommended `DelegatingPasswordEncoder`, bcrypt as default |
| `new DelegatingPasswordEncoder(String idForEncode, Map<String, PasswordEncoder>)` | Manual construction — what the factory does for you |
| `NoOpPasswordEncoder.getInstance()` | No-op comparison — test/demo only, never production |
| `PasswordEncoder.upgradeEncoding(String)` | Signals whether a stored value should be re-encoded on next successful login |

### `src/main/java/com/labs/formauth/credentials/PasswordEncoderConfig.java` (modified — comments only, behavior unchanged)
```java
package com.labs.formauth.credentials;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        // This is a DelegatingPasswordEncoder, not a plain BCryptPasswordEncoder.
        // encode() always uses bcrypt (today's default id) and prepends "{bcrypt}".
        // matches() ignores that default entirely and reads whatever {id} is
        // actually stored on the value being checked. See Topic 2.5.
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
```

### `src/test/java/com/labs/formauth/credentials/PasswordEncoderMechanicsTest.java`
```java
package com.labs.formauth.credentials;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PasswordEncoderMechanicsTest {

    @Test
    void bcryptOutputFormat() {
        // Part A: what the stored string actually looks like, byte for byte.
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(); // default strength = 10
        String encoded = encoder.encode("password123");
        System.out.println("[2.5] raw bcrypt output: " + encoded);

        // $2a$ = version | 10 = cost factor (2^10 rounds) | next 22 chars = salt | rest = hash
        String[] parts = encoded.split("\\$");
        System.out.println("[2.5] version=" + parts[1] + ", cost=" + parts[2]);
        assertThat(encoded).startsWith("$2a$10$");
    }

    @Test
    void identicalPasswordsProduceDifferentStoredValues() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String first = encoder.encode("password123");
        String second = encoder.encode("password123");
        System.out.println("[2.5] first : " + first);
        System.out.println("[2.5] second: " + second);

        assertThat(first).isNotEqualTo(second);          // different salts
        assertThat(encoder.matches("password123", first)).isTrue();   // both still verify
        assertThat(encoder.matches("password123", second)).isTrue();
    }

    @Test
    void costFactorControlsSpeedDirectly() {
        BCryptPasswordEncoder cheap = new BCryptPasswordEncoder(4);   // 2^4  = 16 rounds
        BCryptPasswordEncoder normal = new BCryptPasswordEncoder(10); // 2^10 = 1024 rounds

        long t0 = System.nanoTime();
        cheap.encode("password123");
        long cheapMs = (System.nanoTime() - t0) / 1_000_000;

        long t1 = System.nanoTime();
        normal.encode("password123");
        long normalMs = (System.nanoTime() - t1) / 1_000_000;

        System.out.println("[2.5] cost=4  took " + cheapMs + "ms");
        System.out.println("[2.5] cost=10 took " + normalMs + "ms");
        // Same algorithm, exponentially more rounds - normal should be
        // dramatically slower on any machine, not just marginally.
    }

    @Test
    void delegatingEncoderTagsTheAlgorithmUsed() {
        PasswordEncoder delegating = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        String encoded = delegating.encode("password123");
        System.out.println("[2.5] delegating output: " + encoded);
        assertThat(encoded).startsWith("{bcrypt}$2a$");
    }

    @Test
    void delegatingEncoderReadsStoredPrefixNotTodaysDefault() {
        // Simulates a legacy value tagged with an OLD algorithm id.
        // Topic 2.4's StaticUserStore used exactly this format: "{noop}password123"
        PasswordEncoder delegating = PasswordEncoderFactories.createDelegatingPasswordEncoder();

        String legacyValue = "{noop}password123";
        System.out.println("[2.5] matching against legacy {noop} value...");
        assertThat(delegating.matches("password123", legacyValue)).isTrue();
        // bcrypt was never invoked here - the {noop} prefix routed this to the
        // no-op decoder, regardless of what today's default encoder is.
    }

    @Test
    void missingIdPrefixThrowsRatherThanGuessing() {
        // THE TRAP, reproduced exactly: a raw bcrypt hash stored WITHOUT
        // going through DelegatingPasswordEncoder has no {id} at all.
        PasswordEncoder delegating = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        String noPrefixHash = new BCryptPasswordEncoder().encode("password123");
        System.out.println("[2.5] stored value with no id prefix: " + noPrefixHash);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> delegating.matches("password123", noPrefixHash));
        System.out.println("[2.5] threw as expected: " + ex.getMessage());
    }

    @Test
    void manualConstructionRevealsWhatTheFactoryHides() {
        // What PasswordEncoderFactories.createDelegatingPasswordEncoder() does
        // for you invisibly, built here by hand instead.
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("bcrypt", new BCryptPasswordEncoder());
        encoders.put("noop", NoOpPasswordEncoder.getInstance());

        DelegatingPasswordEncoder manual = new DelegatingPasswordEncoder("bcrypt", encoders);
        String encoded = manual.encode("password123");
        System.out.println("[2.5] manually-built delegating output: " + encoded);

        assertThat(encoded).startsWith("{bcrypt}");
        assertThat(manual.matches("password123", "{noop}password123")).isTrue();
    }

    @Test
    void upgradeEncodingSignalsMigration() {
        PasswordEncoder delegating = PasswordEncoderFactories.createDelegatingPasswordEncoder();

        boolean legacyShouldUpgrade = delegating.upgradeEncoding("{noop}password123");
        boolean currentShouldUpgrade = delegating.upgradeEncoding(delegating.encode("password123"));

        System.out.println("[2.5] {noop} value needs upgrade? " + legacyShouldUpgrade);
        System.out.println("[2.5] current-default value needs upgrade? " + currentShouldUpgrade);

        assertThat(legacyShouldUpgrade).isTrue();     // not on today's default -> flag it
        assertThat(currentShouldUpgrade).isFalse();   // already current -> nothing to do
    }
}
```

### Run it

```
mvn test -Dtest=PasswordEncoderMechanicsTest
```

**Expected:** 8 tests pass. Watch the console output, not just the green summary:
- `bcryptOutputFormat` prints a real `$2a$10$...` string — go count the segments yourself against Part A's breakdown.
- `costFactorControlsSpeedDirectly` prints two millisecond values where cost=10 is noticeably slower than cost=4 — this is Part A's "deliberately slow" claim, timed on your own machine, not asserted.
- `missingIdPrefixThrowsRatherThanGuessing` prints the exact exception message — the trap, reproduced, not described.

### Contrast experiment

Comment out `encoders.put("noop", NoOpPasswordEncoder.getInstance());` in `manualConstructionRevealsWhatTheFactoryHides`, then change the final assertion's target from `"{noop}password123"` to the same value — rerun just that test:
```
mvn test -Dtest=PasswordEncoderMechanicsTest#manualConstructionRevealsWhatTheFactoryHides
```
**Expected:** `IllegalArgumentException: No password encoder mapped for the id "noop"` — a *different* failure from the "missing prefix" trap. That one was "no id at all"; this one is "an id was given, but nothing's registered to handle it." Both are real, distinct production failure modes for the same underlying reason: `DelegatingPasswordEncoder` will never silently guess.

### Try it yourself

1. Change `new BCryptPasswordEncoder(10)` to `new BCryptPasswordEncoder(12)` in `costFactorControlsSpeedDirectly`. Rerun — the jump from 10→12 is 2 more bits, so 4× the rounds. Does the printed time roughly reflect that, on your machine?
2. In `delegatingEncoderReadsStoredPrefixNotTodaysDefault`, add a second assertion checking `delegating.matches("password123", delegating.encode("password123"))` right after the `{noop}` one, and print both results side by side. Confirm both return `true` despite going through completely different decoders internally.
3. Add a new test that calls `PasswordEncoderFactories.createDelegatingPasswordEncoder().matches("password123", "{unknown}somehash")` — an id that's a real-looking string but isn't registered in the factory's map at all. Is the exception message different from the "id null" trap's message? This tells apart "no id" from "unrecognized id" at the source level, not just by description.

### Delta

**Added:** `src/test/java/com/labs/formauth/credentials/PasswordEncoderMechanicsTest.java`
**Modified:** `credentials/PasswordEncoderConfig.java` (comments only — no behavior change)