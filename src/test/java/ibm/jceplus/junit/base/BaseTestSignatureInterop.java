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

public class BaseTestSignatureInterop extends BaseTestJunit5Interop {

    protected void doSignVerify(String sigAlgo, byte[] message, PrivateKey privateKey,
            PublicKey publicKey) throws Exception {
        doSignVerify(sigAlgo, message, privateKey, publicKey, getProviderName(), getInteropProviderName());
        doSignVerify(sigAlgo, message, privateKey, publicKey, getInteropProviderName(), getProviderName());
    }


    protected static void doSignVerify(String sigAlgo, byte[] message, PrivateKey privateKey,
            PublicKey publicKey, String signProvider, String verifyProvider) throws Exception {
        Signature signing = Signature.getInstance(sigAlgo, signProvider);
        signing.initSign(privateKey);
        signing.update(message);
        byte[] signedBytes = signing.sign();

        Signature verifying = Signature.getInstance(sigAlgo, verifyProvider);
        verifying.initVerify(publicKey);
        verifying.update(message);

        assertTrue(verifying.verify(signedBytes), "Signature verification failed");
    }
}

