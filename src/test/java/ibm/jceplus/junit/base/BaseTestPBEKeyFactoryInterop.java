/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.SecureRandom;
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
 * PBE supported algorithms.
 */
public class BaseTestPBEKeyFactoryInterop extends BaseTestJunit5Interop {

    final String PASSWORD = "Thequickbrownfoxjumpsoverthelazydog";
    byte[] randomSalt = new byte[32];
    SecureRandom random = new SecureRandom();
    PBEKeySpec pbeks = null;

    @BeforeAll
    public void setUp() {
        random.nextBytes(randomSalt);
        this.pbeks = new PBEKeySpec(PASSWORD.toCharArray());
    }
    /**
     * Test used to perform interoperability tests using a KeyFactory for
     * the method `getAlgorithm()`.
     */
    @ParameterizedTest
    @CsvSource({"PBEWithHmacSHA1AndAES_128", "PBEWithHmacSHA1AndAES_256", "PBEWithHmacSHA224AndAES_128", "PBEWithHmacSHA224AndAES_256",
        "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_128", "PBEWithHmacSHA384AndAES_256",
        "PBEWithHmacSHA512AndAES_128", "PBEWithHmacSHA512AndAES_256", "PBEWithHmacSHA512/224AndAES_128", "PBEWithHmacSHA512/224AndAES_256",
        "PBEWithHmacSHA512/256AndAES_128", "PBEWithHmacSHA512/256AndAES_256"})
    public void testGetAlgorithm(String algorithm) throws Exception {

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
    @CsvSource({"PBEWithHmacSHA1AndAES_128", "PBEWithHmacSHA1AndAES_256", "PBEWithHmacSHA224AndAES_128", "PBEWithHmacSHA224AndAES_256",
        "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_128", "PBEWithHmacSHA384AndAES_256",
        "PBEWithHmacSHA512AndAES_128", "PBEWithHmacSHA512AndAES_256", "PBEWithHmacSHA512/224AndAES_128", "PBEWithHmacSHA512/224AndAES_256",
        "PBEWithHmacSHA512/256AndAES_128", "PBEWithHmacSHA512/256AndAES_256"})
    public void testGetEncoding(String algorithm) throws Exception {

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
    @CsvSource({"PBEWithHmacSHA1AndAES_128", "PBEWithHmacSHA1AndAES_256", "PBEWithHmacSHA224AndAES_128", "PBEWithHmacSHA224AndAES_256",
        "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_128", "PBEWithHmacSHA384AndAES_256",
        "PBEWithHmacSHA512AndAES_128", "PBEWithHmacSHA512AndAES_256", "PBEWithHmacSHA512/224AndAES_128", "PBEWithHmacSHA512/224AndAES_256",
        "PBEWithHmacSHA512/256AndAES_128", "PBEWithHmacSHA512/256AndAES_256"})
    public void testTranslate(String algorithm) throws Exception {

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
    @CsvSource({"PBEWithHmacSHA1AndAES_128", "PBEWithHmacSHA1AndAES_256", "PBEWithHmacSHA224AndAES_128", "PBEWithHmacSHA224AndAES_256",
        "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_128", "PBEWithHmacSHA384AndAES_256",
        "PBEWithHmacSHA512AndAES_128", "PBEWithHmacSHA512AndAES_256", "PBEWithHmacSHA512/224AndAES_128", "PBEWithHmacSHA512/224AndAES_256",
        "PBEWithHmacSHA512/256AndAES_128", "PBEWithHmacSHA512/256AndAES_256"})
    public void testKeySpec(String algorithm) throws Exception {

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
    @CsvSource({"PBEWithHmacSHA1AndAES_128", "PBEWithHmacSHA1AndAES_256", "PBEWithHmacSHA224AndAES_128", "PBEWithHmacSHA224AndAES_256",
        "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_128", "PBEWithHmacSHA384AndAES_256",
        "PBEWithHmacSHA512AndAES_128", "PBEWithHmacSHA512AndAES_256", "PBEWithHmacSHA512/224AndAES_128", "PBEWithHmacSHA512/224AndAES_256",
        "PBEWithHmacSHA512/256AndAES_128", "PBEWithHmacSHA512/256AndAES_256"})
    public void testHashCode(String algorithm) throws Exception {

        SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
        SecretKeyFactory skfInterop = SecretKeyFactory.getInstance(algorithm,
                this.getInteropProviderName());
        SecretKey sk1 = skf.generateSecret(pbeks);
        SecretKey skInterop = skfInterop.generateSecret(pbeks);
        assertEquals(sk1.hashCode(), skInterop.hashCode(), "Hash codes do not match." + algorithm);
    }

    /**
     * Test used to perform interoperability tests using a KeyFactory for
     * the method `equals()`.
     */
    @ParameterizedTest
    @CsvSource({"PBEWithHmacSHA1AndAES_128", "PBEWithHmacSHA1AndAES_256", "PBEWithHmacSHA224AndAES_128", "PBEWithHmacSHA224AndAES_256",
        "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_128", "PBEWithHmacSHA384AndAES_256",
        "PBEWithHmacSHA512AndAES_128", "PBEWithHmacSHA512AndAES_256", "PBEWithHmacSHA512/224AndAES_128", "PBEWithHmacSHA512/224AndAES_256",
        "PBEWithHmacSHA512/256AndAES_128", "PBEWithHmacSHA512/256AndAES_256"})
    public void testEquality(String algorithm) throws Exception {

        SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
        SecretKeyFactory skfInterop = SecretKeyFactory.getInstance(algorithm,
                this.getInteropProviderName());
        SecretKey sk1 = skf.generateSecret(pbeks);
        SecretKey skInterop = skfInterop.generateSecret(pbeks);
        assertTrue(sk1.equals(skInterop), "Keys are not equal between different providers." + algorithm);
        assertTrue(sk1.equals(sk1), "Keys are not equal when key is exactly the same.");

        PBEKeySpec pbeksDifferent = new PBEKeySpec("DifferentPW".toCharArray());
        SecretKey skDifferent = skf.generateSecret(pbeksDifferent);
        assertFalse(sk1.equals(skDifferent), "Keys are not expected to be equal.");
    }

    /**
     * Test used to perform interoperability tests using a SecretKey generated
     * by a providers KeyFactory for the method `getFormat()`.
     */
    @ParameterizedTest
    @CsvSource({"PBEWithHmacSHA1AndAES_128", "PBEWithHmacSHA1AndAES_256", "PBEWithHmacSHA224AndAES_128", "PBEWithHmacSHA224AndAES_256",
        "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_128", "PBEWithHmacSHA384AndAES_256",
        "PBEWithHmacSHA512AndAES_128", "PBEWithHmacSHA512AndAES_256", "PBEWithHmacSHA512/224AndAES_128", "PBEWithHmacSHA512/224AndAES_256",
        "PBEWithHmacSHA512/256AndAES_128", "PBEWithHmacSHA512/256AndAES_256"})
    public void testGetFormat(String algorithm) throws Exception {

        SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
        SecretKeyFactory skfInterop = SecretKeyFactory.getInstance(algorithm,
                this.getInteropProviderName());
        SecretKey sk1 = skf.generateSecret(pbeks);
        SecretKey skInterop = skfInterop.generateSecret(pbeks);
        assertEquals(sk1.getFormat(), skInterop.getFormat(), "Format does not match.");
    }
}
