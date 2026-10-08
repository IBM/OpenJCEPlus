/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Tests for SecureRandom (SHA256DRBG and SHA512DRBG) covering the native
 * functions that are reachable from the Java layer:
 *
 *   EXTRAND_create     -- exercised by HASHDRBG constructor (PRNGContextPointer)
 *   EXTRAND_nextBytes  -- exercised by engineNextBytes -> SecureRandom.nextBytes()
 *   EXTRAND_setSeed    -- exercised by engineSetSeed  -> SecureRandom.setSeed()
 *   EXTRAND_delete     -- exercised by GC cleaner after setSeed creates instance ctx
 *   RAND_generateSeed  -- exercised by engineGenerateSeed -> SecureRandom.generateSeed()
 *
 * RAND_nextBytes and RAND_setSeed (BasicRandom) are not tested here because
 * they are unreachable dead code in the current provider - no call site in
 * HASHDRBG or anywhere else routes through BasicRandom.nextBytes/setSeed.
 *
 * This test class covers the OCK backend only.
 * OpenSSL-backend coverage will be added in a follow-up PR once
 * OpenSSLOnly.config registers both SHA256DRBG and SHA512DRBG with
 * NativeProvider=OpenSSL.
 */
@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
public class TestSecureRandom extends BaseTest {

    @Parameter(0)
    TestProvider provider;

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
    }

    // -----------------------------------------------------------------------
    // EXTRAND_create + EXTRAND_nextBytes via SHA256DRBG
    // -----------------------------------------------------------------------

    @Test
    public void testNextBytes_SHA256DRBG() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA256DRBG", getProviderName());
        assertNotNull(sr);

        byte[] bytes = new byte[32];
        sr.nextBytes(bytes);

        assertFalse(isAllZeros(bytes), "nextBytes output should not be all zeros");
    }

    @Test
    public void testNextBytes_SHA512DRBG() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA512DRBG", getProviderName());
        assertNotNull(sr);

        byte[] bytes = new byte[64];
        sr.nextBytes(bytes);

        assertFalse(isAllZeros(bytes), "nextBytes output should not be all zeros");
    }

    // -----------------------------------------------------------------------
    // Two consecutive calls must produce different output
    // -----------------------------------------------------------------------

    @Test
    public void testNextBytes_SHA256DRBG_consecutive() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA256DRBG", getProviderName());
        byte[] first  = new byte[32];
        byte[] second = new byte[32];
        sr.nextBytes(first);
        sr.nextBytes(second);

        assertFalse(Arrays.equals(first, second),
                "Consecutive nextBytes calls should produce different output");
    }

    @Test
    public void testNextBytes_SHA512DRBG_consecutive() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA512DRBG", getProviderName());
        byte[] first  = new byte[64];
        byte[] second = new byte[64];
        sr.nextBytes(first);
        sr.nextBytes(second);

        assertFalse(Arrays.equals(first, second),
                "Consecutive nextBytes calls should produce different output");
    }

    // -----------------------------------------------------------------------
    // RAND_generateSeed via engineGenerateSeed
    // -----------------------------------------------------------------------

    @Test
    public void testGenerateSeed_SHA256DRBG() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA256DRBG", getProviderName());
        byte[] seed = sr.generateSeed(32);

        assertNotNull(seed);
        assertEquals(32, seed.length, "generateSeed should return exactly 32 bytes");
        assertFalse(isAllZeros(seed), "generateSeed output should not be all zeros");
    }

    @Test
    public void testGenerateSeed_SHA512DRBG() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA512DRBG", getProviderName());
        byte[] seed = sr.generateSeed(64);

        assertNotNull(seed);
        assertEquals(64, seed.length, "generateSeed should return exactly 64 bytes");
        assertFalse(isAllZeros(seed), "generateSeed output should not be all zeros");
    }

    @Test
    public void testGenerateSeed_zeroLength() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA256DRBG", getProviderName());
        byte[] seed = sr.generateSeed(0);
        assertNotNull(seed, "generateSeed(0) should return empty array, not null");
        assertEquals(0, seed.length, "generateSeed(0) should return 0-length array");
    }

    // -----------------------------------------------------------------------
    // EXTRAND_setSeed + EXTRAND_delete via engineSetSeed
    // setSeed switches HASHDRBG from thread-local to instance context,
    // exercising EXTRAND_create (for instance ctx) and scheduling
    // EXTRAND_delete via the GC cleaner.
    // -----------------------------------------------------------------------

    @Test
    public void testSetSeed_SHA256DRBG() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA256DRBG", getProviderName());
        byte[] seed = new byte[32];
        for (int i = 0; i < seed.length; i++) seed[i] = (byte) (i + 1);

        sr.setSeed(seed);

        byte[] bytes = new byte[32];
        sr.nextBytes(bytes);
        assertFalse(isAllZeros(bytes), "nextBytes after setSeed should not be all zeros");
    }

    @Test
    public void testSetSeed_SHA512DRBG() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA512DRBG", getProviderName());
        byte[] seed = new byte[64];
        for (int i = 0; i < seed.length; i++) seed[i] = (byte) (i + 1);

        sr.setSeed(seed);

        byte[] bytes = new byte[64];
        sr.nextBytes(bytes);
        assertFalse(isAllZeros(bytes), "nextBytes after setSeed should not be all zeros");
    }

    // -----------------------------------------------------------------------
    // Cross-instance: two independent instances must not produce identical
    // output (verifies each has its own independent DRBG state)
    // -----------------------------------------------------------------------

    @Test
    public void testCrossInstance_SHA256DRBG() throws Exception {
        SecureRandom sr1 = SecureRandom.getInstance("SHA256DRBG", getProviderName());
        SecureRandom sr2 = SecureRandom.getInstance("SHA256DRBG", getProviderName());

        byte[] out1 = new byte[32];
        byte[] out2 = new byte[32];
        sr1.nextBytes(out1);
        sr2.nextBytes(out2);

        assertFalse(Arrays.equals(out1, out2),
                "Two independent SHA256DRBG instances should not produce identical output");
    }

    @Test
    public void testCrossInstance_SHA512DRBG() throws Exception {
        SecureRandom sr1 = SecureRandom.getInstance("SHA512DRBG", getProviderName());
        SecureRandom sr2 = SecureRandom.getInstance("SHA512DRBG", getProviderName());

        byte[] out1 = new byte[64];
        byte[] out2 = new byte[64];
        sr1.nextBytes(out1);
        sr2.nextBytes(out2);

        assertFalse(Arrays.equals(out1, out2),
                "Two independent SHA512DRBG instances should not produce identical output");
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    private static boolean isAllZeros(byte[] bytes) {
        for (byte b : bytes) {
            if (b != 0) return false;
        }
        return true;
    }
}
