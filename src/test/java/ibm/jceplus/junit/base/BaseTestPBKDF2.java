/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Tests associated with PBKDF2 algorithms.
 * 
 */
public class BaseTestPBKDF2 extends BaseTestJunit5Interop {
    List<String> allowableFIPSAlgorithms = new ArrayList<String>(){{
            add("PBKDF2WithHmacSHA224");
            add("PBKDF2WithHmacSHA256");
            add("PBKDF2WithHmacSHA384");
            add("PBKDF2WithHmacSHA512");
        }};

    /**
    * Official test vector from RFC 7914.
    * 
    * 11.  Test Vectors for PBKDF2 with HMAC-SHA-256
    * 
    * Below is a sequence of octets that illustrate input and output values
    * for PBKDF2-HMAC-SHA-256.  The octets are hex encoded and whitespace
    * is inserted for readability.  The test vectors below can be used to
    * verify the PBKDF2-HMAC-SHA-256 [RFC2898] function.  The password and
    * salt strings are passed as sequences of ASCII [RFC20] octets.
    *
    * PBKDF2-HMAC-SHA-256 (P="passwd", S="salt",
    *                     c=1, dkLen=64) =
    * 55 ac 04 6e 56 e3 08 9f ec 16 91 c2 25 44 b6 05
    * f9 41 85 21 6d de 04 65 e6 8b 9d 57 c2 0d ac bc
    * 49 ca 9c cc f1 79 b6 45 99 16 64 b3 9d 77 ef 31
    * 7c 71 b8 45 b1 e3 0b d5 09 11 20 41 d3 a1 97 83
    *
    * PBKDF2-HMAC-SHA-256 (P="Password", S="NaCl",
    *                      c=80000, dkLen=64) =
    * 4d dc d8 f6 0b 98 be 21 83 0c ee 5e f2 27 01 f9
    * 64 1a 44 18 d0 4c 04 14 ae ff 08 87 6b 34 ab 56
    * a1 d4 25 a1 22 58 33 54 9a db 84 1b 51 c9 b3 17
    * 6a 27 2b de bb a1 d0 78 47 8f 62 b3 97 f3 3c 8d
    *
    * @param algorithm
    * @throws Exception
    */
    @Test
    public void testPBKDF2KAT() throws Exception {

        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256",
                        this.getProviderName());
        PBEKeySpec pbeks = new PBEKeySpec("passwd".toCharArray(), "salt".getBytes("ASCII"),
                        1, 512);
        SecretKey sk = skf.generateSecret(pbeks);
        String hexKeyValue = BaseUtils.bytesToHex(sk.getEncoded());
        assertEquals("55ac046e56e3089fec1691c22544b605" +
                     "f94185216dde0465e68b9d57c20dacbc" +
                     "49ca9cccf179b645991664b39d77ef31" +
                     "7c71b845b1e30bd509112041d3a19783", hexKeyValue,
                        "RFC Known answer test failed for PBKDF2WithHmacSHA256.");
        pbeks = new PBEKeySpec("Password".toCharArray(), "NaCl".getBytes("ASCII"), 80000,
                        512);
        sk = skf.generateSecret(pbeks);
        hexKeyValue = BaseUtils.bytesToHex(sk.getEncoded());
        assertEquals("4ddcd8f60b98be21830cee5ef22701f9" +
                     "641a4418d04c0414aeff08876b34ab56" +
                     "a1d425a1225833549adb841b51c9b317" +
                     "6a272bdebba1d078478f62b397f33c8d", hexKeyValue,
                        "RFC Known answer test failed for PBKDF2WithHmacSHA256.");
    }

    @ParameterizedTest
    @CsvSource({"PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA224", "PBKDF2WithHmacSHA256",
        "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512", "PBKDF2WithHmacSHA512/224", "PBKDF2WithHmacSHA512/256"})
    public void testAlgorithmExistence(String algorithm) throws Exception {
        try {
            SecretKeyFactory.getInstance(algorithm, this.getProviderName());
        } catch (NoSuchAlgorithmException e) {
            // The FIPS provider does not allow for PBKDF2WithHmacSHA1 and PBKDF2WithHmacSHA224.
            if ((!isSupportedByOpenJCEPlusFIPS(algorithm)) && this.getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
                return;
            } else {
                throw e;
            }
        }
    }

    @ParameterizedTest
    @CsvSource({"PBKDF2WithHmacSHA224", "PBKDF2WithHmacSHA256",
        "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512", "PBKDF2WithHmacSHA512/224", "PBKDF2WithHmacSHA512/256"})
    public void testSmallSalt(String algorithm) throws Exception {
        
        PBEKeySpec pbeks = new PBEKeySpec("ABCDEFGHIJ".toCharArray(), "SmallSalt".getBytes(), 10000, 512);
        if (this.getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
            if (isSupportedByOpenJCEPlusFIPS(algorithm)) {
                try {
                    SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
                    skf.generateSecret(pbeks);
                    fail("Expected an exception due to salt < 128 for OpenJCEPlusFIPS provider for algorithm: " + algorithm + ", but none was thrown.");
                } catch(InvalidKeySpecException e) {
                    assertEquals("Salt must be 128 bits or higher when using the OpenJCEPlusFIPS provider.", e.getMessage());
                }
            } else {
                try {
                    SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
                    skf.generateSecret(pbeks);
                    fail("Expected NoSuchAlgorithmException for non FIPS certified algorithm: " + algorithm + ", but none was thrown.");
                } catch(NoSuchAlgorithmException e) {
                    assertEquals("no such algorithm: " + algorithm + " for provider OpenJCEPlusFIPS", e.getMessage());
                }
            }
        } else {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
            skf.generateSecret(pbeks);
        }
    }

    @ParameterizedTest
    @CsvSource({"PBKDF2WithHmacSHA224", "PBKDF2WithHmacSHA256",
        "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512", "PBKDF2WithHmacSHA512/224", "PBKDF2WithHmacSHA512/256"})
    public void testSmallIterationCount(String algorithm) throws Exception {
        PBEKeySpec pbeks = new PBEKeySpec("ABCDEFGHIJ".toCharArray(), new byte[32], 999, 512);
        if (this.getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
            if (isSupportedByOpenJCEPlusFIPS(algorithm)) {
                try {
                    SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
                    skf.generateSecret(pbeks);
                    fail("Expected an exception due to iteration count < 1000 for OpenJCEPlusFIPS provider for algorithm: " + algorithm + ", but none was thrown.");
                } catch(InvalidKeySpecException e) {
                    assertEquals("Iteration count must be 1000 or higher when using the OpenJCEPlusFIPS provider.", e.getMessage());
                }
            } else {
                try {
                    SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
                    skf.generateSecret(pbeks);
                    fail("Expected NoSuchAlgorithmException for non FIPS certified algorithm: " + algorithm + ", but none was thrown.");
                } catch(NoSuchAlgorithmException e) {
                    assertEquals("no such algorithm: " + algorithm + " for provider OpenJCEPlusFIPS", e.getMessage());
                }
            }
        } else {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
            skf.generateSecret(pbeks);
        }
    }

    @ParameterizedTest
    @CsvSource({"PBKDF2WithHmacSHA224", "PBKDF2WithHmacSHA256",
        "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512", "PBKDF2WithHmacSHA512/224", "PBKDF2WithHmacSHA512/256"})
    public void testSmallKeyLength(String algorithm) throws Exception {
        PBEKeySpec pbeks = new PBEKeySpec("ABCDEFGHIJ".toCharArray(), new byte[32], 8000, 111);
        if (this.getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
            if (isSupportedByOpenJCEPlusFIPS(algorithm)) {
                try {
                    SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
                    skf.generateSecret(pbeks);
                    fail("Expected an exception due to key length < 112 for OpenJCEPlusFIPS provider for algorithm: " + algorithm + ", but none was thrown.");
                } catch(InvalidKeySpecException e) {
                    assertEquals("Key length must be 112 bits or higher when using the OpenJCEPlusFIPS provider.", e.getMessage());
                }
            } else {
                try {
                    SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
                    skf.generateSecret(pbeks);
                    fail("Expected NoSuchAlgorithmException for non FIPS certified algorithm: " + algorithm + ", but none was thrown.");
                } catch(NoSuchAlgorithmException e) {
                    assertEquals("no such algorithm: " + algorithm + " for provider OpenJCEPlusFIPS", e.getMessage());
                }
            }
        } else {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
            skf.generateSecret(pbeks);
        }
    }

    @ParameterizedTest
    @CsvSource({"PBKDF2WithHmacSHA224", "PBKDF2WithHmacSHA256",
        "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512", "PBKDF2WithHmacSHA512/224", "PBKDF2WithHmacSHA512/256"})
    public void testShortPassword(String algorithm) throws Exception {
        PBEKeySpec pbeks = new PBEKeySpec("ABCDEFGHI".toCharArray(), new byte[32], 1000, 112);
        if (this.getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
            if (isSupportedByOpenJCEPlusFIPS(algorithm)) {
                try {
                    SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
                    skf.generateSecret(pbeks);
                    fail("Expected an exception due to password length < 10 for OpenJCEPlusFIPS provider for algorithm: " + algorithm + ", but none was thrown.");
                } catch(InvalidKeySpecException e) {
                    assertEquals("Password must be 10 characters or higher when using the OpenJCEPlusFIPS provider.", e.getMessage());
                }
            } else {
                try {
                    SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
                    skf.generateSecret(pbeks);
                    fail("Expected NoSuchAlgorithmException for non FIPS certified algorithm: " + algorithm + ", but none was thrown.");
                } catch(NoSuchAlgorithmException e) {
                    assertEquals("no such algorithm: " + algorithm + " for provider OpenJCEPlusFIPS", e.getMessage());
                }
            }
        } else {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
            skf.generateSecret(pbeks);
        }
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
