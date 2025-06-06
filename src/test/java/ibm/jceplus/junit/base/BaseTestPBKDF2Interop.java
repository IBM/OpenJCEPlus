/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests to perform interoperability tests between a provider under test,
 * typically OpenJCEPlus or OpenJCEPlusFIPS and another provider for
 * PBKDF2 supported algorithms.
 */
public class BaseTestPBKDF2Interop extends BaseTestJunit5Interop {

    final String PASSWORD = "Thequickbrownfoxjumpsoverthelazydog";
    byte[] randomSalt = new byte[32];
    SecureRandom random = new SecureRandom();
    PBEKeySpec pbeks = null;
    List<String> allowableFIPSAlgorithms = new ArrayList<String>(){{
            add("PBKDF2WithHmacSHA224");
            add("PBKDF2WithHmacSHA256");
            add("PBKDF2WithHmacSHA384");
            add("PBKDF2WithHmacSHA512");
        }};

    @BeforeAll
    public void setUp() {
        random.nextBytes(randomSalt);
        this.pbeks = new PBEKeySpec(PASSWORD.toCharArray(), randomSalt, 5000, 112);
    }
    /**
     * Test used to perform interoperability tests using a KeyFactory for
     * the method `getAlgorithm()`.
     */
    @ParameterizedTest
    @CsvSource({"PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA224", "PBKDF2WithHmacSHA256",
            "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512"})
    public void testGetAlgorithm(String algorithm) throws Exception {

        if ((!isSupportedByOpenJCEPlusFIPS(algorithm))
                && this.getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
            return;
        }

        SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
        SecretKeyFactory skfInterop = SecretKeyFactory.getInstance(algorithm,
                this.getInteropProviderName());

        // Validate that the algorithm name from provider under test matches the interop provider.
        System.out.println("    Checking getAlgorithm()");
        assertEquals(skf.getAlgorithm(), skfInterop.getAlgorithm(),
                "Algorithm name is not as expected.");
    }

    /**
     * Test used to perform interoperability tests using a KeyFactory for
     * the method `getEncoded()`.
     */
    @ParameterizedTest
    @CsvSource({"PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA224", "PBKDF2WithHmacSHA256",
            "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512"})
    public void testGetEncoding(String algorithm) throws Exception {

        if ((!isSupportedByOpenJCEPlusFIPS(algorithm))
                && this.getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
            return;
        }

        SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
        SecretKeyFactory skfInterop = SecretKeyFactory.getInstance(algorithm,
                this.getInteropProviderName());

        // Validate key encodings generated from provider under test matches the interop provider.
        SecretKey sk1 = skf.generateSecret(pbeks);
        SecretKey skInterop = skfInterop.generateSecret(pbeks);
        assertArrayEquals(sk1.getEncoded(), skInterop.getEncoded(), "Key encodings do not match.");
    }

    /**
     * Test used to perform interoperability tests using a KeyFactory for
     * the method `translateKey()`.
     */
    @ParameterizedTest
    @CsvSource({"PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA224", "PBKDF2WithHmacSHA256",
            "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512"})
    public void testTranslate(String algorithm) throws Exception {

        if ((!isSupportedByOpenJCEPlusFIPS(algorithm))
                && this.getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
            return;
        }

        SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
        SecretKeyFactory skfInterop = SecretKeyFactory.getInstance(algorithm,
                this.getInteropProviderName());

        // Validate key translations of the same key generated from provider under test matches the interop provider.
        System.out.println("    Checking translateKey()");
        SecretKey sk1 = skf.generateSecret(pbeks);
        SecretKey skInterop = skfInterop.generateSecret(pbeks);
        SecretKey sk1T = skf.translateKey(sk1);
        SecretKey skInteropT = skf.translateKey(skInterop);
        assertArrayEquals(sk1T.getEncoded(), skInteropT.getEncoded(),
                "Translated keys do not match.");
        SecretKey sk1TI = skfInterop.translateKey(sk1);
        SecretKey skInteropTI = skfInterop.translateKey(skInterop);
        assertArrayEquals(sk1TI.getEncoded(), skInteropTI.getEncoded(),
                "Translated keys do not match.");
    }

    /**
     * Test used to perform interoperability tests using a KeyFactory for
     * the method `getKeySpec()`.
     */
    @ParameterizedTest
    @CsvSource({"PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA224", "PBKDF2WithHmacSHA256",
            "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512"})
    public void testKeySpec(String algorithm) throws Exception {

        if ((!isSupportedByOpenJCEPlusFIPS(algorithm))
                && this.getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
            return;
        }

        SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
        SecretKeyFactory skfInterop = SecretKeyFactory.getInstance(algorithm,
                this.getInteropProviderName());

        // Validate that the key spec produced by the provider under test matches the interop provider.
        System.out.println("    Checking getKeySpec()");
        SecretKey sk1 = skf.generateSecret(pbeks);
        SecretKey skInterop = skfInterop.generateSecret(pbeks);
        PBEKeySpec ks1 = (PBEKeySpec) skf.getKeySpec(sk1, PBEKeySpec.class);
        PBEKeySpec ksInterop = (PBEKeySpec) skfInterop.getKeySpec(skInterop, PBEKeySpec.class);
        assertEquals(ks1.getIterationCount(), ksInterop.getIterationCount(),
                "Iteration count does not match.");
        assertEquals(ks1.getKeyLength(), ksInterop.getKeyLength(), "Key length does not match.");
        assertArrayEquals(ks1.getPassword(), ksInterop.getPassword(), "Password does not match.");
        assertArrayEquals(ks1.getSalt(), ksInterop.getSalt(), "Salt does not match.");
    }

    /**
     * Test used to perform interoperability tests using a KeyFactory for
     * the method `hashCode()`.
     */
    @ParameterizedTest
    @CsvSource({"PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA224", "PBKDF2WithHmacSHA256",
            "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512"})
    public void testHashCode(String algorithm) throws Exception {

        if ((!isSupportedByOpenJCEPlusFIPS(algorithm))
                && this.getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
            return;
        }

        SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
        SecretKeyFactory skfInterop = SecretKeyFactory.getInstance(algorithm,
                this.getInteropProviderName());
        SecretKey sk1 = skf.generateSecret(pbeks);
        SecretKey skInterop = skfInterop.generateSecret(pbeks);
        assertEquals(sk1.hashCode(), skInterop.hashCode(), "Hash codes do not match.");
    }

    /**
     * Test used to perform interoperability tests using a KeyFactory for
     * the method `equals()`.
     */
    @ParameterizedTest
    @CsvSource({"PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA224", "PBKDF2WithHmacSHA256",
            "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512"})
    public void testEquality(String algorithm) throws Exception {

        if ((!isSupportedByOpenJCEPlusFIPS(algorithm))
                && this.getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
            return;
        }

        SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
        SecretKeyFactory skfInterop = SecretKeyFactory.getInstance(algorithm,
                this.getInteropProviderName());
        SecretKey sk1 = skf.generateSecret(pbeks);
        SecretKey skInterop = skfInterop.generateSecret(pbeks);
        assertTrue(sk1.equals(skInterop), "Keys are not equal between different providers.");
        assertTrue(sk1.equals(sk1), "Keys are not equal when key is exactly the same.");
        PBEKeySpec pbeksDifferent = new PBEKeySpec("DifferentPW".toCharArray(), randomSalt,
                5000, 112);
        SecretKey skDifferent = skf.generateSecret(pbeksDifferent);
        assertFalse(sk1.equals(skDifferent), "Keys are not expected to be equal.");
    }

    /**
     * Test used to perform interoperability tests using a SecretKey generated
     * by a providers KeyFactory for the method `getFormat()`.
     */
    @ParameterizedTest
    @CsvSource({"PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA224", "PBKDF2WithHmacSHA256",
            "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512"})
    public void testGetFormat(String algorithm) throws Exception {

        if ((!isSupportedByOpenJCEPlusFIPS(algorithm))
                && this.getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
            return;
        }

        SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
        SecretKeyFactory skfInterop = SecretKeyFactory.getInstance(algorithm,
                this.getInteropProviderName());
        SecretKey sk1 = skf.generateSecret(pbeks);
        SecretKey skInterop = skfInterop.generateSecret(pbeks);
        assertEquals(sk1.getFormat(), skInterop.getFormat(), "Format does not match.");

    }

    /**
     * Method to help determine if the OpenJCEPlusFIPS provider supports an algorithm.
     * 
     * @param algorithm
     * @return
     */
    private boolean isSupportedByOpenJCEPlusFIPS(String algorithm) {
        for (String allowed : allowableFIPSAlgorithms) {
            if (allowed.equalsIgnoreCase(algorithm)) {
                return true;
            }
        }
        return false;
    }
}
