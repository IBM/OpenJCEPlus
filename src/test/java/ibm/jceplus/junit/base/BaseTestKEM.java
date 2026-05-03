/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestKEM extends BaseTestJunit5 {


    protected KeyPairGenerator pqcKeyPairGen;
    protected KeyFactory pqcKeyFactory;

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_768", "ML_KEM_1024"})
    public void testKEM(String Algorithm) throws Exception {

        KEM kem = KEM.getInstance(Algorithm, getProviderName());

        KeyPair pqcKeyPair = generateKeyPair(Algorithm);

        KEM.Encapsulator encr = kem.newEncapsulator(pqcKeyPair.getPublic());
        KEM.Encapsulated enc = encr.encapsulate(0, 32, "AES");

        SecretKey keyE = enc.key();
       
        KEM.Decapsulator decr = kem.newDecapsulator(pqcKeyPair.getPrivate());
        SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 32, "AES");
        
        assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_768", "ML_KEM_1024"})
    public void testKEMEmptyNoToFrom(String Algorithm) throws Exception {

        KEM kem = KEM.getInstance(Algorithm, getProviderName());

        KeyPair pqcKeyPair = generateKeyPair(Algorithm);

        KEM.Encapsulator encr = kem.newEncapsulator(pqcKeyPair.getPublic());
        KEM.Encapsulated enc = encr.encapsulate();

        SecretKey keyE = enc.key();
       
        KEM.Decapsulator decr = kem.newDecapsulator(pqcKeyPair.getPrivate());
        SecretKey keyD = decr.decapsulate(enc.encapsulation());
        
        assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_768", "ML_KEM_1024"})
    public void testKEMError(String Algorithm) throws Exception {
        KEM.Encapsulated enc = null;

        KEM kem = KEM.getInstance(Algorithm, getProviderName());

        KeyPair pqcKeyPair = generateKeyPair(Algorithm);

        KEM.Encapsulator encr = kem.newEncapsulator(pqcKeyPair.getPublic());
        for (int i = 0; i < 4; i++) {
            int from = 0;
            int to = 0;
            switch (i) {
                case 0:
                    from = 0;
                    to = 33;
                    break;
                case 1:
                    from = -1;
                    to = 32;
                    break;
                case 2:
                    from = 20;
                    to = 15;
                    break;
                case 3:
                    from = 32;
                    to = 32;
                    break;
            }
            try {
                enc = encr.encapsulate(from, to, "AES");
                fail("testKEMError failed -Encapsulated length's test failed.");
            } catch (IndexOutOfBoundsException iob) {
            }
        }

        try {
            enc = encr.encapsulate(0, 32, null);
            fail("testKEMError failed -Encapsulated null alg worked.");
        } catch (NullPointerException iob) {
        }

        enc = encr.encapsulate(0, 32, "AES");
       
        KEM.Decapsulator decr = kem.newDecapsulator(pqcKeyPair.getPrivate());
        for (int i = 0; i < 4; i++) {
            int from = 0;
            int to = 0;
            switch (i) {
                case 0:
                    from = 0;
                    to = 33;
                    break;
                case 1:
                    from = -1;
                    to = 32;
                    break;
                case 2:
                    from = 20;
                    to = 15;
                    break;
                case 3:
                    from = 32;
                    to = 32;
                    break;
            }
            try {
                decr.decapsulate(enc.encapsulation(), from, to, "AES");
                fail("testKEMError failed -Decapsulate length's test failed.");
            } catch (IndexOutOfBoundsException iob) {
            }
        }

        try {
            decr.decapsulate(enc.encapsulation(), 0, 32, null);
            fail("testKEMError failed -Decapsulate alg null worked.");
        } catch (NullPointerException iob) {
        }
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_768", "ML_KEM_1024"})
    public void testKEMSmallerSecret(String Algorithm) throws Exception {

        KEM kem = KEM.getInstance(Algorithm, getProviderName());

        KeyPair pqcKeyPair = generateKeyPair(Algorithm);

        KEM.Encapsulator encr = kem.newEncapsulator(pqcKeyPair.getPublic());
        KEM.Encapsulated enc = encr.encapsulate(0, 16, "AES");

        SecretKey keyE = enc.key();

        KEM.Decapsulator decr = kem.newDecapsulator(pqcKeyPair.getPrivate());
        SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 16, "AES");
        
        assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_768", "ML_KEM_1024"})
    public void testKEMKeys(String Algorithm) throws Exception {

        KEM kem = KEM.getInstance(Algorithm, getProviderName());

        KeyPair pqcKeyPair = generateKeyPair("RSA");

        try {
            kem.newEncapsulator(pqcKeyPair.getPublic());
            fail("testKEMKeys failed - RSA Public key did not cause an InvalidKeyException.");
        } catch (InvalidKeyException ike) {
            assertTrue(ike.getMessage().equals("unsupported key"));
        }
  
        try {
            kem.newDecapsulator(pqcKeyPair.getPrivate());
            fail("testKEMKeys failed - RSA Private key did not cause an InvalidKeyException.");
        } catch (InvalidKeyException ike) {
            assertTrue(ike.getMessage().equals("unsupported key"));
        }

        // Test null keys
        PublicKey pub = null;
        PrivateKey priv = null;

        try {
            kem.newEncapsulator(pub);
            fail("testKEMKeys failed - NULL Public key did not cause an InvalidKeyException.");
        } catch (InvalidKeyException ike) {
            assertTrue(ike.getMessage().equals("Key is null."));
        }
  
        try {
            kem.newDecapsulator(priv);
            fail("testKEMKeys failed - NULL Private key did not cause an InvalidKeyException.");
        } catch (InvalidKeyException ike) {
            assertTrue(ike.getMessage().equals("Key is null."));
        }
    }

    /**
     * Tests that decapsulation fails with a DecapsulateException when attempting to decapsulate
     * an encapsulation message that was created with a different ML-KEM algorithm variant.
     *
     * <p>This test verifies that the KEM implementation properly validates the encapsulation
     * message length during decapsulation. Each ML-KEM variant (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
     * produces encapsulation messages of different lengths. When a decapsulator receives an
     * encapsulation message with an incorrect length (from a different variant), it should
     * reject it with a DecapsulateException containing an appropriate error message.
     *
     * <p>Test procedure:
     * <ol>
     *   <li>Generate a key pair using the first algorithm (keyAlgorithm)</li>
     *   <li>Generate a different key pair using a second algorithm (wrongAlgorithm)</li>
     *   <li>Create an encapsulation using the second key pair (wrong length for first algorithm)</li>
     *   <li>Attempt to decapsulate using the first key pair's private key</li>
     *   <li>Verify that a DecapsulateException is thrown with the expected error message</li>
     * </ol>
     *
     * @param keyAlgorithm the ML-KEM algorithm variant to use for the decapsulation key pair
     * @param wrongAlgorithm the ML-KEM algorithm variant to use for creating the encapsulation
     *                       (produces wrong length for keyAlgorithm)
     * @throws Exception if an unexpected error occurs during test execution
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512,ML-KEM-768", "ML-KEM-768,ML-KEM-1024", "ML-KEM-1024,ML-KEM-512"})
    public void testKEMInvalidEncapsulationLength(String keyAlgorithm, String wrongAlgorithm) throws Exception {
        // Generate a key pair with one algorithm
        KeyPair keyPair = generateKeyPair(keyAlgorithm);
        
        // Create encapsulation with a different algorithm (wrong length)
        KEM kemWrong = KEM.getInstance(wrongAlgorithm, getProviderName());
        KeyPair wrongKeyPair = generateKeyPair(wrongAlgorithm);
        KEM.Encapsulator encapsulator = kemWrong.newEncapsulator(wrongKeyPair.getPublic());
        KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, 32, "AES");
        
        // Try to decapsulate with the original key (wrong length)
        KEM kem = KEM.getInstance(keyAlgorithm, getProviderName());
        KEM.Decapsulator decapsulator = kem.newDecapsulator(keyPair.getPrivate());
        
        try {
            decapsulator.decapsulate(encapsulated.encapsulation(), 0, 32, "AES");
            fail("testKEMInvalidEncapsulationLength failed - Invalid encapsulation length did not cause a DecapsulateException for " + keyAlgorithm + " with " + wrongAlgorithm + " encapsulation");
        } catch (javax.crypto.DecapsulateException de) {
            assertTrue(de.getMessage().contains("Invalid key encapsulation message length"),
                "Expected error message about invalid encapsulation length, but got: " + de.getMessage());
            assertTrue(de.getMessage().contains(keyAlgorithm),
                "Expected error message to mention key algorithm " + keyAlgorithm + ", but got: " + de.getMessage());
        }
    }

    /**
     * Tests that KEM operations fail with InvalidKeyException when the key algorithm
     * does not match the KEM instance algorithm.
     *
     * <p>This test verifies that when you create a KEM instance for a specific ML-KEM variant
     * (e.g., ML-KEM-768), you cannot use keys from a different variant (e.g., ML-KEM-512).
     * The implementation should validate that the key's algorithm matches the KEM instance's
     * algorithm and reject mismatched keys.
     *
     * <p>Test procedure:
     * <ol>
     *   <li>Create a KEM instance for one algorithm (e.g., ML-KEM-768)</li>
     *   <li>Generate a key pair using a different algorithm (e.g., ML-KEM-512)</li>
     *   <li>Attempt to create an encapsulator with the mismatched public key</li>
     *   <li>Verify that an InvalidKeyException is thrown</li>
     *   <li>Attempt to create a decapsulator with the mismatched private key</li>
     *   <li>Verify that an InvalidKeyException is thrown</li>
     * </ol>
     *
     * @param kemAlgorithm the ML-KEM algorithm variant to use for the KEM instance
     * @param keyAlgorithm the ML-KEM algorithm variant to use for generating the key pair
     * @throws Exception if an unexpected error occurs during test execution
     */
    @ParameterizedTest
    @CsvSource({
        "ML-KEM-512,ML-KEM-768",
        "ML-KEM-512,ML-KEM-1024",
        "ML-KEM-768,ML-KEM-512",
        "ML-KEM-768,ML-KEM-1024",
        "ML-KEM-1024,ML-KEM-512",
        "ML-KEM-1024,ML-KEM-768"
    })
    public void testKEMAlgorithmMismatch(String kemAlgorithm, String keyAlgorithm) throws Exception {
        // Create KEM instance with one algorithm
        KEM kem = KEM.getInstance(kemAlgorithm, getProviderName());
        
        // Generate key pair with a different algorithm
        KeyPair keyPair = generateKeyPair(keyAlgorithm);
        
        // Test encapsulator - should fail with algorithm mismatch
        try {
            kem.newEncapsulator(keyPair.getPublic());
            fail("testKEMAlgorithmMismatch failed - Creating encapsulator with " + keyAlgorithm +
                 " key for " + kemAlgorithm + " KEM instance should throw InvalidKeyException");
        } catch (InvalidKeyException ike) {
            String expectedMessage = "Key algorithm " + keyAlgorithm +
                " does not match KEM instance algorithm " + kemAlgorithm;
            assertEquals(expectedMessage, ike.getMessage());
        }
        
        // Test decapsulator - should fail with algorithm mismatch
        try {
            kem.newDecapsulator(keyPair.getPrivate());
            fail("testKEMAlgorithmMismatch failed - Creating decapsulator with " + keyAlgorithm +
                 " key for " + kemAlgorithm + " KEM instance should throw InvalidKeyException");
        } catch (InvalidKeyException ike) {
            String expectedMessage = "Key algorithm " + keyAlgorithm +
                " does not match KEM instance algorithm " + kemAlgorithm;
            assertEquals(expectedMessage, ike.getMessage());
        }
    }

    /**
     * Tests that the generic "ML-KEM" KEM instance works with all ML-KEM parameter sets.
     *
     * <p>This test verifies that when you create a KEM instance using the generic "ML-KEM"
     * algorithm name, it should accept keys from any ML-KEM variant (ML-KEM-512, ML-KEM-768,
     * or ML-KEM-1024). The generic instance should be flexible and work with all parameter sets.
     *
     * <p>Test procedure:
     * <ol>
     *   <li>Create a generic KEM instance using "ML-KEM"</li>
     *   <li>Generate a key pair using a specific parameter set (e.g., ML-KEM-512)</li>
     *   <li>Create an encapsulator with the key pair's public key</li>
     *   <li>Perform encapsulation to generate a shared secret</li>
     *   <li>Create a decapsulator with the key pair's private key</li>
     *   <li>Perform decapsulation and verify the shared secrets match</li>
     * </ol>
     *
     * @param keyAlgorithm the specific ML-KEM parameter set to use for key generation
     * @throws Exception if an unexpected error occurs during test execution
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testGenericMLKEMWithAllParameterSets(String keyAlgorithm) throws Exception {
        // Create generic ML-KEM instance
        KEM kem = KEM.getInstance("ML-KEM", getProviderName());
        
        // Generate key pair with specific parameter set
        KeyPair keyPair = generateKeyPair(keyAlgorithm);
        
        // Test encapsulation and decapsulation - should work with generic ML-KEM
        KEM.Encapsulator encapsulator = kem.newEncapsulator(keyPair.getPublic());
        KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, 32, "AES");
        
        SecretKey encapKey = encapsulated.key();
        byte[] encapsulation = encapsulated.encapsulation();
        
        KEM.Decapsulator decapsulator = kem.newDecapsulator(keyPair.getPrivate());
        SecretKey decapKey = decapsulator.decapsulate(encapsulation, 0, 32, "AES");
        
        assertArrayEquals(encapKey.getEncoded(), decapKey.getEncoded(),
            "Generic ML-KEM should work with " + keyAlgorithm + " keys - secrets do not match");
    }

    protected KeyPair generateKeyPair(String Algorithm) throws Exception {
        pqcKeyPairGen = KeyPairGenerator.getInstance(Algorithm, getProviderName());

        KeyPair keyPair = pqcKeyPairGen.generateKeyPair();
        if (keyPair.getPrivate() == null) {
            fail("Private key is null");
        }

        if (keyPair.getPublic() == null) {
            fail("RPublic key is null");
        }

        if (!(keyPair.getPrivate() instanceof PrivateKey)) {
            fail("Key is not a PrivateKey");
        }

        if (!(keyPair.getPublic() instanceof PublicKey)) {
            fail("Key is not a PublicKey");
        }

        return keyPair;
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_768", "ML_KEM_1024"})
    protected void keyFactoryCreateFromEncoded(String Algorithm) throws Exception {

        pqcKeyFactory = KeyFactory.getInstance(Algorithm, getProviderName());
        KeyPair pqcKeyPair = generateKeyPair(Algorithm);
        
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(pqcKeyPair.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(
                pqcKeyPair.getPrivate().getEncoded());

        PublicKey pub =  pqcKeyFactory.generatePublic(x509Spec);
        PrivateKey priv =  pqcKeyFactory.generatePrivate(pkcs8Spec);

        assertArrayEquals(pub.getEncoded(), pqcKeyPair.getPublic().getEncoded(),
                    "Public key does not match generated public key");
        assertArrayEquals(priv.getEncoded(), pqcKeyPair.getPrivate().getEncoded(),
                    "Private key does not match generated public key");
    }
}

