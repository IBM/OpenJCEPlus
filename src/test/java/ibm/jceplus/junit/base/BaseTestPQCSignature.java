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
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

public class BaseTestPQCSignature extends BaseTestJunit5Signature {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML_DSA_44", "ML-DSA-65", "ML_DSA_87"})
    public void testPQCKeySignature(String Algorithm) throws Exception {

        KeyPair keyPair = generateKeyPair(Algorithm);
        doSignVerify(Algorithm, origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML_DSA_44", "ML-DSA-65", "ML_DSA_87"})
    public void testPQCKeySignatureEncodings(String Algorithm) throws Exception {

        KeyPair keyPair = generateKeyPair(Algorithm);

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        byte[] publicKeyBytes = publicKey.getEncoded();
        byte[] privateKeyBytes = privateKey.getEncoded();

        KeyFactory keyFactory = KeyFactory.getInstance(Algorithm, getProviderName());
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        doSignVerify(Algorithm, origMsg, keyFactory.generatePrivate(privateKeySpec), keyFactory.generatePublic(publicKeySpec));
    }

    /**
     * Tests that Signature.getInstance("ML-DSA") — the generic family-name
     * signature instance — can sign and verify with keys from each of the three
     * ML-DSA parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87).
     * <p>
     * Per JEP 497, the generic "ML-DSA" Signature must be flexible and accept
     * any ML-DSA parameter-set key. Currently OpenJCEPlus maps the "ML-DSA"
     * Signature alias to ML-DSA-65, so using ML-DSA-44 or ML-DSA-87 keys with
     * the generic instance throws InvalidKeyException.
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testGenericMLDSASignatureWithAllParamSets(String paramSetName)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        // Generate a key pair with the specific parameter set
        KeyPair kp = generateKeyPair(paramSetName);

        // Obtain a GENERIC "ML-DSA" Signature instance
        Signature sig = Signature.getInstance("ML-DSA", getProviderName());

        // Sign — initSign must accept any ML-DSA parameter-set private key
        try {
            sig.initSign(kp.getPrivate());
        } catch (InvalidKeyException e) {
            fail("Generic ML-DSA Signature.initSign() rejected " + paramSetName
                    + " private key: " + e.getMessage());
            return;
        }
        sig.update(origMsg);
        byte[] sigBytes = sig.sign();

        // Verify — initVerify must accept any ML-DSA parameter-set public key
        try {
            sig.initVerify(kp.getPublic());
        } catch (InvalidKeyException e) {
            fail("Generic ML-DSA Signature.initVerify() rejected " + paramSetName
                    + " public key: " + e.getMessage());
            return;
        }
        sig.update(origMsg);
        assertTrue(sig.verify(sigBytes),
                "Generic ML-DSA signature verification failed for " + paramSetName);
    }

    /**
     * Tests that a key generated with KeyPairGenerator("ML-DSA") — which by
     * default produces an ML-DSA-65 key — can be used directly with the generic
     * Signature.getInstance("ML-DSA") without any parameter mismatch error.
     */
    @Test
    public void testGenericMLDSASignatureWithGenericKeyGen() throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        KeyPair kp = generateKeyPair("ML-DSA");

        // Key algorithm should be the family name
        assertEquals("ML-DSA", kp.getPublic().getAlgorithm(),
                "getAlgorithm() on KPG(\"ML-DSA\") public key should return \"ML-DSA\"");
        assertEquals("ML-DSA", kp.getPrivate().getAlgorithm(),
                "getAlgorithm() on KPG(\"ML-DSA\") private key should return \"ML-DSA\"");

        Signature sig = Signature.getInstance("ML-DSA", getProviderName());
        sig.initSign(kp.getPrivate());
        sig.update(origMsg);
        byte[] sigBytes = sig.sign();

        sig.initVerify(kp.getPublic());
        sig.update(origMsg);
        assertTrue(sig.verify(sigBytes),
                "Generic ML-DSA sign/verify round-trip failed for ML-DSA (default param set)");
    }

    /**
     * Tests that a generic "ML-DSA" Signature can round-trip sign/verify when
     * keys are decoded through the generic "ML-DSA" KeyFactory.  This mirrors
     * the usage pattern described in JEP 497.
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testGenericMLDSASignatureWithGenericKeyFactory(String paramSetName)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        KeyPair kp = generateKeyPair(paramSetName);

        // Decode keys via generic "ML-DSA" KeyFactory
        KeyFactory genericKF = KeyFactory.getInstance("ML-DSA", getProviderName());
        PublicKey  pub  = genericKF.generatePublic(
                new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        PrivateKey priv = genericKF.generatePrivate(
                new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        // Verify the re-decoded public key bytes are identical
        assertArrayEquals(kp.getPublic().getEncoded(), pub.getEncoded(),
                "Generic KF re-encoded public key bytes differ for " + paramSetName);

        // Sign with generic Signature + KF-decoded private key
        Signature sig = Signature.getInstance("ML-DSA", getProviderName());
        sig.initSign(priv);
        sig.update(origMsg);
        byte[] sigBytes = sig.sign();

        // Verify with generic Signature + KF-decoded public key
        sig.initVerify(pub);
        sig.update(origMsg);
        assertTrue(sig.verify(sigBytes),
                "Generic ML-DSA Signature + generic KF round-trip failed for " + paramSetName);
    }

    protected KeyPair generateKeyPair(String Algorithm) throws Exception {
        KeyPairGenerator pqcKeyPairGen = KeyPairGenerator.getInstance(Algorithm, getProviderName());

        return pqcKeyPairGen.generateKeyPair();
    }

}

