/*
 * Copyright IBM Corp. 2024, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplusfips;

import ibm.jceplus.junit.base.BaseTestECDHKeyAgreementParamValidation;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.KeyAgreement;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@TestInstance(Lifecycle.PER_CLASS)
public class TestECDHKeyAgreementParamValidation extends BaseTestECDHKeyAgreementParamValidation {

    @BeforeAll
    public void beforeAll() throws Exception {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    @ParameterizedTest
    @ValueSource(strings = {"secp192r1", "secp224r1"})
    public void testECDHKeyAgreementSharedSecretComputation(String curveName) {
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
