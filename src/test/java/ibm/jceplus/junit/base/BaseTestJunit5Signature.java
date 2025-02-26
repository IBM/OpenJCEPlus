/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestJunit5Signature extends BaseTestJunit5 {

    protected void doSignVerify(String sigAlgo, byte[] message, PrivateKey privateKey,
            PublicKey publicKey) throws Exception {
        Signature signing = Signature.getInstance(sigAlgo, getProviderName());
        signing.initSign(privateKey);
        signing.update(message);
        byte[] signedBytes = signing.sign();

        Signature verifying = Signature.getInstance(sigAlgo, getProviderName());
        verifying.initVerify(publicKey);
        verifying.update(message);

        assertTrue(verifying.verify(signedBytes), "Signature verification failed");
    }
}
