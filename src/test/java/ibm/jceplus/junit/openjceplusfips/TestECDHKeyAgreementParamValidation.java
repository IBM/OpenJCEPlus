/*
 * Copyright IBM Corp. 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.openjceplusfips;

import ibm.jceplus.junit.base.BaseTestECDHKeyAgreementParamValidation;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@TestInstance(Lifecycle.PER_CLASS)
public class TestECDHKeyAgreementParamValidation extends BaseTestECDHKeyAgreementParamValidation {

    @BeforeAll
    public void beforeAll() throws Exception {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    @ParameterizedTest
    @ValueSource(strings = {"secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160r1", "secp160r2", "secp160k1", "secp192k1", "secp192r1"})
    public void testECDHKeyAgreementSharedSecretComputation(String curveName) {
        try {
            KeyPair alice = genECKeyPair(curveName);
            KeyPair bob   = genECKeyPair(curveName);

            byte[] secretAlice = ecdhSharedSecretComputation(alice.getPrivate(), bob.getPublic());
            byte[] secretBob   = ecdhSharedSecretComputation(bob.getPrivate(), alice.getPublic());
        } catch (Exception e) {
            assertTrue(e.getMessage().equals(curveName + " curve is not supported in FIPS"));
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
