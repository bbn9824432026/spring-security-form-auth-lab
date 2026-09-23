package com.labs.formauth.credentials;

class PasswordEncoderMechanicsTest {

    /*@Test
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
    }*/
}