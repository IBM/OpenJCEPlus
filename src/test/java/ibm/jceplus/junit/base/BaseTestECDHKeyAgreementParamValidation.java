/*
 * Copyright IBM Corp. 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECPrivateKeySpec;
import javax.crypto.KeyAgreement;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestECDHKeyAgreementParamValidation extends BaseTestJunit5 {

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
}
