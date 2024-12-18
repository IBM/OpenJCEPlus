/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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

