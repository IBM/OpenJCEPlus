/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

@Tag(Tags.OPENJCEPLUS_OPENSSL_NAME)
@Tag(Tags.OPENJCEPLUS_OCK_NAME)
@Tag(Tags.MULTITHREAD_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
@EnabledForJreRange(min = JRE.JAVA_17)
public class TestPQCSignature extends BaseTestSignature {

    @Parameter(0)
    TestProvider provider;

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML_DSA_44", "ML-DSA-65", "ML_DSA_87",
        "SLH-DSA", "SLH_DSA_SHA2_128s", "SLH-DSA-SHA2-128s", "SLH_DSA_SHA2_128f", "SLH-DSA-SHA2-128f",
        "SLH_DSA_SHA2_192s", "SLH-DSA-SHA2-192s", "SLH_DSA_SHA2_192f", "SLH-DSA-SHA2-192f",
        "SLH_DSA_SHA2_256s", "SLH-DSA-SHA2-256s", "SLH_DSA_SHA2_256f", "SLH-DSA-SHA2-256f",
        "SLH_DSA_SHAKE_128s", "SLH-DSA-SHAKE-128s", "SLH_DSA_SHAKE_128f", "SLH-DSA-SHAKE-128f",
        "SLH_DSA_SHAKE_192s", "SLH-DSA-SHAKE-192s", "SLH_DSA_SHAKE_192f", "SLH-DSA-SHAKE-192f",
        "SLH_DSA_SHAKE_256s", "SLH-DSA-SHAKE-256s", "SLH_DSA_SHAKE_256f", "SLH-DSA-SHAKE-256f"})
    public void testPQCKeySignature(String Algorithm) throws Exception {
        assumeFalse(BaseUtils.isSLHDSA(Algorithm) && !BaseUtils.isOpenSSLProvider(getProviderName()));

        KeyPair keyPair = generateKeyPair(Algorithm);
        doSignVerify(Algorithm, origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML_DSA_44", "ML-DSA-65", "ML_DSA_87",
        "SLH-DSA", "SLH_DSA_SHA2_128s", "SLH-DSA-SHA2-128s", "SLH_DSA_SHA2_128f", "SLH-DSA-SHA2-128f",
        "SLH_DSA_SHA2_192s", "SLH-DSA-SHA2-192s", "SLH_DSA_SHA2_192f", "SLH-DSA-SHA2-192f",
        "SLH_DSA_SHA2_256s", "SLH-DSA-SHA2-256s", "SLH_DSA_SHA2_256f", "SLH-DSA-SHA2-256f",
        "SLH_DSA_SHAKE_128s", "SLH-DSA-SHAKE-128s", "SLH_DSA_SHAKE_128f", "SLH-DSA-SHAKE-128f",
        "SLH_DSA_SHAKE_192s", "SLH-DSA-SHAKE-192s", "SLH_DSA_SHAKE_192f", "SLH-DSA-SHAKE-192f",
        "SLH_DSA_SHAKE_256s", "SLH-DSA-SHAKE-256s", "SLH_DSA_SHAKE_256f", "SLH-DSA-SHAKE-256f"})
    public void testPQCKeySignatureEncodings(String Algorithm) throws Exception {
        assumeFalse(BaseUtils.isSLHDSA(Algorithm) && !BaseUtils.isOpenSSLProvider(getProviderName()));

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
     * Tests that Signature.getInstance(family) - the generic family-name
     * signature instance - can sign and verify with keys from each parameter set.
     */
    @ParameterizedTest
    @CsvSource({
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
    })
    public void testGenericPQCSignatureWithAllParamSets(String paramSetName)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(BaseUtils.isSLHDSA(paramSetName) && !BaseUtils.isOpenSSLProvider(getProviderName()));

        String family = BaseUtils.getFamilyName(paramSetName);

        // Generate a key pair with the specific parameter set
        KeyPair kp = generateKeyPair(paramSetName);

        // Obtain a GENERIC Signature instance (e.g. "ML-DSA" or "SLH-DSA")
        Signature sig = Signature.getInstance(family, getProviderName());

        // Sign - initSign must accept any parameter-set private key in the family
        try {
            sig.initSign(kp.getPrivate());
        } catch (InvalidKeyException e) {
            fail("Generic " + family + " Signature.initSign() rejected " + paramSetName
                    + " private key: " + e.getMessage());
            return;
        }
        sig.update(origMsg);
        byte[] sigBytes = sig.sign();

        // Verify - initVerify must accept any parameter-set public key in the family
        try {
            sig.initVerify(kp.getPublic());
        } catch (InvalidKeyException e) {
            fail("Generic " + family + " Signature.initVerify() rejected " + paramSetName
                    + " public key: " + e.getMessage());
            return;
        }
        sig.update(origMsg);
        assertTrue(sig.verify(sigBytes),
                "Generic " + family + " signature verification failed for " + paramSetName);
    }

    /**
     * Tests that a key generated with KeyPairGenerator(family) - which
     * produces a default parameter-set key - can be used directly with the generic
     * Signature.getInstance(family) without any parameter mismatch error.
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA", "SLH-DSA"})
    public void testGenericPQCSignatureWithGenericKeyGen(String family) throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(BaseUtils.isSLHDSA(family) && !BaseUtils.isOpenSSLProvider(getProviderName()));

        KeyPair kp = generateKeyPair(family);

        // Key algorithm should be the family name
        assertEquals(family, kp.getPublic().getAlgorithm(),
                "getAlgorithm() on KPG(\"" + family + "\") public key should return \"" + family + "\"");
        assertEquals(family, kp.getPrivate().getAlgorithm(),
                "getAlgorithm() on KPG(\"" + family + "\") private key should return \"" + family + "\"");

        Signature sig = Signature.getInstance(family, getProviderName());
        sig.initSign(kp.getPrivate());
        sig.update(origMsg);
        byte[] sigBytes = sig.sign();

        sig.initVerify(kp.getPublic());
        sig.update(origMsg);
        assertTrue(sig.verify(sigBytes),
                "Generic " + family + " sign/verify round-trip failed for " + family + " (default param set)");
    }

    /**
     * Tests that a generic family Signature can round-trip sign/verify when
     * keys are decoded through the generic family KeyFactory.
     */
    @ParameterizedTest
    @CsvSource({
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
    })
    public void testGenericPQCSignatureWithGenericKeyFactory(String paramSetName)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(BaseUtils.isSLHDSA(paramSetName) && !BaseUtils.isOpenSSLProvider(getProviderName()));

        String family = BaseUtils.getFamilyName(paramSetName);

        KeyPair kp = generateKeyPair(paramSetName);

        // Decode keys via generic KeyFactory (e.g. "ML-DSA" or "SLH-DSA")
        KeyFactory genericKF = KeyFactory.getInstance(family, getProviderName());
        PublicKey  pub  = genericKF.generatePublic(
                new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        PrivateKey priv = genericKF.generatePrivate(
                new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        // Verify the re-decoded public key bytes are identical
        assertArrayEquals(kp.getPublic().getEncoded(), pub.getEncoded(),
                "Generic KF re-encoded public key bytes differ for " + paramSetName);

        // Sign with generic Signature + KF-decoded private key
        Signature sig = Signature.getInstance(family, getProviderName());
        sig.initSign(priv);
        sig.update(origMsg);
        byte[] sigBytes = sig.sign();

        // Verify with generic Signature + KF-decoded public key
        sig.initVerify(pub);
        sig.update(origMsg);
        assertTrue(sig.verify(sigBytes),
                "Generic " + family + " Signature + generic KF round-trip failed for " + paramSetName);
    }

    protected KeyPair generateKeyPair(String Algorithm) throws Exception {
        KeyPairGenerator pqcKeyPairGen = KeyPairGenerator.getInstance(Algorithm, getProviderName());

        return pqcKeyPairGen.generateKeyPair();
    }

}

