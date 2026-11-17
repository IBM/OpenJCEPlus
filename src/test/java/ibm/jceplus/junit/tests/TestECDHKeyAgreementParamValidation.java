/*
 * Copyright IBM Corp. 2024, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import javax.crypto.KeyAgreement;
import javax.crypto.ShortBufferException;
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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
public class TestECDHKeyAgreementParamValidation extends BaseTest {

    @Parameter(0)
    TestProvider provider;

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
    }

    @Test
    public void testInitWithInvalidKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", getProviderName());
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();

        KeyFactory keyFactory = KeyFactory.getInstance("EC", getProviderName());
        ECPrivateKey invalidPrivateKey
                = (ECPrivateKey) keyFactory.generatePrivate(
                        new ECPrivateKeySpec(BigInteger.ZERO,
                                privateKey.getParams()));

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", getProviderName());

        // The first initialization should succeed.
        ka.init(privateKey);

        // The second initialization should fail with invalid private key,
        // and the private key assigned by the first initialization should be cleared.
        try {
            ka.init(invalidPrivateKey);
            fail("Expected <java.security.InvalidKeyException> to be thrown");
        } catch (java.security.InvalidKeyException ike) {
            System.out.println("Expected <java.security.InvalidKeyException> is caught.");
        }
    }

    @Test
    public void testECDHKeyAgreementShortBuffer() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", getProviderName());
        final int KEYSIZE = 256;
        kpg.initialize(KEYSIZE);
        KeyPair kp = kpg.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", getProviderName());
        ka.init(privateKey);
        ka.doPhase(publicKey, true);
        try {
            ka.generateSecret(new byte[1], 0);
            fail("Expected exception not thrown.");
        } catch (ShortBufferException e) {
            assertEquals("Need " + KEYSIZE / 8 + " bytes, only 1 available", e.getMessage());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"secp192r1", "secp224r1"})
    public void testECDHKeyAgreementSharedSecretComputation(String curveName) {
        assumeTrue("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeTrue(
            Boolean.getBoolean("openjceplus.disableSmallerECKeySizeForSharedKeyComputing"),
            "Property not true; skipping"
        );

        try {
            KeyPair alice = genECKeyPair(curveName);
            KeyPair bob   = genECKeyPair(curveName);

            ecdhSharedSecretComputation(alice.getPrivate(), bob.getPublic());
            ecdhSharedSecretComputation(bob.getPrivate(), alice.getPublic());

            fail("Curve " + curveName + " worked unexpectedly");
        } catch (Exception e) {
            if (curveName.equals("secp192r1")) {
                assertTrue(e.getMessage().equals("NIST P-192 curve is not supported in FIPS for calculating the shared secret"));
            } else {
                assertTrue(e.getMessage().equals("NIST P-224 curve is not supported in FIPS for calculating the shared secret"));
            }
        }
    }

    private KeyPair genECKeyPair(String curveName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", getProviderName());
        kpg.initialize(new ECGenParameterSpec(curveName));
        KeyPair kp = kpg.generateKeyPair();
        return kp;
    }

    private byte[] ecdhSharedSecretComputation(PrivateKey priv, PublicKey peerPub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", getProviderName());
        ka.init(priv);
        ka.doPhase(peerPub, true);
        return ka.generateSecret();
    }

}
