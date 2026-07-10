/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
public class TestPBMAC1 extends BaseTest {
    
    @Parameter(0)
    TestProvider provider;
    
    private List<String> algorithms = Arrays.asList("PBEWithHmacSHA1", "PBEWithHmacSHA224", "PBEWithHmacSHA256", "PBEWithHmacSHA384", 
            "PBEWithHmacSHA512");
    private List<String> fipsalgorithms = Arrays.asList("PBEWithHmacSHA384", "PBEWithHmacSHA512");

    private final String message = "This is a message for PBMAC1 testing";
    private final char[] PASSWORD = "passwordtryagain".toCharArray();
    private SecureRandom secureRandom = new SecureRandom();
    private byte[] salt = new byte[20];
    private int iterationCount = 300000;

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
    }

    @ParameterizedTest
    @FieldSource("algorithms")
    void testPBMACFunctionality(String alg) throws Exception {
        assumeFalse(getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS") && (alg.equalsIgnoreCase("PBEWithHmacSHA1") || 
             alg.equalsIgnoreCase("PBEWithHmacSHA224") || alg.equalsIgnoreCase("PBEWithHmacSHA256")));
        
        secureRandom.nextBytes(salt);
        SecretKey key = new SecretKeySpec(PASSWORD.toString().getBytes(), alg);
        Mac mac = Mac.getInstance(alg, getProviderName());
        mac.init(key, new PBEParameterSpec(salt, iterationCount));

        byte[] macText = mac.doFinal(message.getBytes());
        assertNotEquals(null, macText, "Mac generated NULL");
        assertEquals(mac.getMacLength(), macText.length);
    }

    @ParameterizedTest
    @FieldSource("algorithms")
    void testPBMACReset(String alg) throws Exception {
        assumeFalse(getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS") && (alg.equalsIgnoreCase("PBEWithHmacSHA1") || 
             alg.equalsIgnoreCase("PBEWithHmacSHA224") || alg.equalsIgnoreCase("PBEWithHmacSHA256")));
    
        secureRandom.nextBytes(salt);
        SecretKey key = new SecretKeySpec(PASSWORD.toString().getBytes(), alg);
        Mac mac = Mac.getInstance(alg, getProviderName());
        mac.init(key, new PBEParameterSpec(salt, iterationCount));

        byte[] macText = mac.doFinal(message.getBytes());

        mac.reset();
        byte[] macText1 = mac.doFinal(message.getBytes());

        assertArrayEquals(macText, macText1);
    }

    @ParameterizedTest
    @FieldSource("algorithms")
    void testPBMACUpdate(String alg) throws Exception {
        assumeFalse(getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS") && (alg.equalsIgnoreCase("PBEWithHmacSHA1") || 
             alg.equalsIgnoreCase("PBEWithHmacSHA224") || alg.equalsIgnoreCase("PBEWithHmacSHA256")));
    
        secureRandom.nextBytes(salt);
        SecretKey key = new SecretKeySpec(PASSWORD.toString().getBytes(), alg);
        Mac mac = Mac.getInstance(alg, getProviderName());
        mac.init(key, new PBEParameterSpec(salt, iterationCount));

        byte[] macText = update(mac, message.getBytes(), 2);

        assertEquals(mac.getMacLength(), macText.length);
    }

    private byte[] update(Mac m, byte[] text, int updateLen) throws Exception {
        m.update(text, 0, updateLen);
        m.update(text, updateLen, updateLen);
        m.update(text, 2 * updateLen, text.length - (2 * updateLen));
        byte[] finalUpdate = m.doFinal();
        
        return finalUpdate;
    }

    @ParameterizedTest
    @FieldSource("algorithms")
    void testPBMACException(String alg) throws Exception {
        assumeFalse(getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS"));

        secureRandom.nextBytes(salt);
        Mac mac = Mac.getInstance(alg, getProviderName());
        SecretKeyFactory kdf = SecretKeyFactory.getInstance("PBKDF2With" + alg.substring(7), getProviderName());

        SecretKey key = (SecretKey) kdf.generateSecret(new PBEKeySpec(PASSWORD, salt, iterationCount, 512));
        mac.init(key, new PBEParameterSpec(salt, iterationCount));
        
        PBEParameterSpec spec = new PBEParameterSpec(salt, iterationCount);

        try {
            SecretKey keyDiffIterationCount = (SecretKey) kdf.generateSecret(new PBEKeySpec(PASSWORD, salt, iterationCount + 5, 512)); 
            mac.init(keyDiffIterationCount, spec);
            fail("Expected InvalidAlgorithmParameterException not thrown, different value of iteration count between key and params");
        } catch (InvalidAlgorithmParameterException e) {
            assertEquals("Different iteration count between key and params", e.getMessage());
        }

        try {
            byte[] saltDiff = new byte[20];
            secureRandom.nextBytes(saltDiff);
            SecretKey keyDiffSalt = (SecretKey) kdf.generateSecret(new PBEKeySpec(PASSWORD, saltDiff, iterationCount, 512)); 
            mac.init(keyDiffSalt, spec);
            fail("Expected InvalidAlgorithmParameterException not thrown, different value of salt between key and params");
        } catch (InvalidAlgorithmParameterException e) {
            assertEquals("Inconsistent value of salt between key and params", e.getMessage());
        }
    }

    @ParameterizedTest
    @FieldSource("fipsalgorithms")
    void testPBMACFIPSExceptions(String alg) throws Exception {
        assumeTrue(getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS"));
        
        secureRandom.nextBytes(salt);
        SecretKey key = new SecretKeySpec(PASSWORD.toString().getBytes(), alg);
        Mac mac = Mac.getInstance(alg, getProviderName());

        try {
            byte[] smallSalt = new byte[8];
            secureRandom.nextBytes(smallSalt);
            mac.init(key, new PBEParameterSpec(smallSalt, iterationCount));
            fail("Expected InvalidKeyException not thrown, small salt length");
        } catch (InvalidKeyException e) {
            assertEquals("Cannot construct PBE key", e.getMessage());
        }

        try {
            mac.init(key, new PBEParameterSpec(salt, 100));
            fail("Expected InvalidKeyException not thrown, small iteration count");
        } catch (InvalidKeyException e) {
            assertEquals("Cannot construct PBE key", e.getMessage());
        }

        try {
            SecretKey smallPasswordKey = new SecretKeySpec("pa".toString().getBytes(), alg);
            mac.init(smallPasswordKey, new PBEParameterSpec(salt, iterationCount));
            fail("Expected InvalidKeyException not thrown, small password length");
        } catch (InvalidKeyException e) {
            assertEquals("Cannot construct PBE key", e.getMessage());
        }
    }
}
