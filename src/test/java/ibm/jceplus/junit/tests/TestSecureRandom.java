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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Tests for SecureRandom (SHA256DRBG and SHA512DRBG) covering the native
 * functions that are reachable from the Java layer:
 *
 * <ul>
 * <li>EXTRAND_create - exercised by the HASHDRBG constructor
 * (PRNGContextPointer)</li>
 * <li>EXTRAND_nextBytes - exercised by engineNextBytes via
 * SecureRandom.nextBytes()</li>
 * <li>EXTRAND_setSeed - exercised by engineSetSeed via
 * SecureRandom.setSeed()</li>
 * <li>EXTRAND_delete - exercised by the GC cleaner after setSeed creates an
 * instance context</li>
 * <li>RAND_generateSeed - exercised by engineGenerateSeed via
 * SecureRandom.generateSeed()</li>
 * </ul>
 */
@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
public class TestSecureRandom extends BaseTest {

    /**
     * Number of bytes requested from the generator. Large enough that an
     * all-zero result is not a realistic outcome of a working generator.
     */
    private static final int NUM_BYTES = 2048;

    /** The provider under test. */
    @Parameter(0)
    TestProvider provider;

    /**
     * Inserts the provider under test before each test.
     */
    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
    }

    /**
     * Verifies that nextBytes fills a buffer with non-zero output
     * (EXTRAND_create and EXTRAND_nextBytes).
     */
    @ParameterizedTest
    @ValueSource(strings = {"SHA256DRBG", "SHA512DRBG"})
    public void testNextBytes(String algorithm) throws Exception {
        SecureRandom sr = SecureRandom.getInstance(algorithm, getProviderName());
        assertNotNull(sr);

        byte[] bytes = new byte[NUM_BYTES];
        sr.nextBytes(bytes);

        assertFalse(isAllZeros(bytes), "nextBytes output should not be all zeros");
    }

    /**
     * Verifies that two consecutive nextBytes calls on the same instance
     * produce different output.
     */
    @ParameterizedTest
    @ValueSource(strings = {"SHA256DRBG", "SHA512DRBG"})
    public void testNextBytesConsecutive(String algorithm) throws Exception {
        SecureRandom sr = SecureRandom.getInstance(algorithm, getProviderName());
        byte[] first = new byte[NUM_BYTES];
        byte[] second = new byte[NUM_BYTES];
        sr.nextBytes(first);
        sr.nextBytes(second);

        assertFalse(Arrays.equals(first, second),
                "Consecutive nextBytes calls should produce different output");
    }

    /**
     * Verifies that generateSeed returns the requested number of non-zero
     * bytes (RAND_generateSeed).
     */
    @ParameterizedTest
    @ValueSource(strings = {"SHA256DRBG", "SHA512DRBG"})
    public void testGenerateSeed(String algorithm) throws Exception {
        SecureRandom sr = SecureRandom.getInstance(algorithm, getProviderName());
        byte[] seed = sr.generateSeed(NUM_BYTES);

        assertNotNull(seed);
        assertEquals(NUM_BYTES, seed.length,
                "generateSeed should return exactly " + NUM_BYTES + " bytes");
        assertFalse(isAllZeros(seed), "generateSeed output should not be all zeros");
    }

    /**
     * Verifies that generateSeed(0) returns an empty array rather than null.
     */
    @Test
    public void testGenerateSeedZeroLength() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA256DRBG", getProviderName());
        byte[] seed = sr.generateSeed(0);
        assertNotNull(seed, "generateSeed(0) should return empty array, not null");
        assertEquals(0, seed.length, "generateSeed(0) should return 0-length array");
    }

    /**
     * Verifies that setSeed followed by nextBytes works. setSeed switches
     * HASHDRBG from the thread-local context to an instance context,
     * exercising EXTRAND_create for the instance context, EXTRAND_setSeed, and
     * scheduling EXTRAND_delete via the GC cleaner.
     */
    @ParameterizedTest
    @ValueSource(strings = {"SHA256DRBG", "SHA512DRBG"})
    public void testSetSeed(String algorithm) throws Exception {
        SecureRandom sr = SecureRandom.getInstance(algorithm, getProviderName());
        byte[] seed = new byte[64];
        for (int i = 0; i < seed.length; i++) {
            seed[i] = (byte) (i + 1);
        }

        sr.setSeed(seed);

        byte[] bytes = new byte[NUM_BYTES];
        sr.nextBytes(bytes);
        assertFalse(isAllZeros(bytes), "nextBytes after setSeed should not be all zeros");
    }

    /**
     * Verifies that two independent instances do not produce identical output,
     * i.e. each has its own DRBG state.
     */
    @ParameterizedTest
    @ValueSource(strings = {"SHA256DRBG", "SHA512DRBG"})
    public void testCrossInstance(String algorithm) throws Exception {
        SecureRandom sr1 = SecureRandom.getInstance(algorithm, getProviderName());
        SecureRandom sr2 = SecureRandom.getInstance(algorithm, getProviderName());

        byte[] out1 = new byte[NUM_BYTES];
        byte[] out2 = new byte[NUM_BYTES];
        sr1.nextBytes(out1);
        sr2.nextBytes(out2);

        assertFalse(Arrays.equals(out1, out2),
                "Two independent " + algorithm + " instances should not produce identical output");
    }

    /**
     * Returns true if every byte in the array is zero.
     */
    private static boolean isAllZeros(byte[] bytes) {
        for (byte b : bytes) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
