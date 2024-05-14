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
import static org.junit.Assert.assertTrue;

public class BaseTestSignature extends BaseTestJunit5 {

    private int keysize = 0;

    private String algo = null;

    /**
     * Sets the algorithm associated with this test.
     * @param algorithm
     */
    public void setAlgorithm(String algorithm) {
        this.algo = algorithm;
    }

    /**
     * Gets the algorithm associated with this test.
     * @return
     */
    public String getAlgorithm() {
        return this.algo;
    }

    /**
     * Sets the key size associated with this test.
     * @param keySize
     */
    public void setKeySize(int keySize) {
        this.keysize = keySize;
    }

    /**
     * Gets the key size associated with this test.
     * @return
     */
    public int getKeySize() {
        return this.keysize;
    }

    protected void doSignVerify(String sigAlgo, byte[] message, PrivateKey privateKey,
            PublicKey publicKey) throws Exception {
        Signature signing = Signature.getInstance(sigAlgo, getProviderName());
        signing.initSign(privateKey);
        signing.update(message);
        byte[] signedBytes = signing.sign();

        Signature verifying = Signature.getInstance(sigAlgo, getProviderName());
        verifying.initVerify(publicKey);
        verifying.update(message);

        assertTrue("Signature verification failed", verifying.verify(signedBytes));
    }
}

