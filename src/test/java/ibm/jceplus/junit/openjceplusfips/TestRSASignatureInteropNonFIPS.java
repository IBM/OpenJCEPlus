/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.openjceplusfips;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import junit.framework.Test;
import junit.framework.TestSuite;

public class TestRSASignatureInteropNonFIPS 
    extends ibm.jceplus.junit.base.BaseTestRSASignatureInterop {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSASignatureInteropNonFIPS() {
        super(Utils.TEST_SUITE_PROVIDER_NAME, Utils.PROVIDER_SunRsaSign, 1024);
    }

    // RSA signature allows at least 2048 bits of RSA key to be used for sign a signature.
    @Override
    protected void doSignVerify(String sigAlgo, byte[] message, PrivateKey privateKey,
            PublicKey publicKey) throws Exception {
        Signature signing = Signature.getInstance(sigAlgo, Utils.TEST_SUITE_PROVIDER_NAME);
        try {
            signing.initSign(privateKey);
        } catch (java.security.InvalidParameterException ipe) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("RSA keys must be at least 2048 bits long", ipe.getMessage());
                return;
            } else {
                throw ipe;
            }
        }
        signing.update(message);
        byte[] signedBytes = signing.sign();

        Signature verifying = Signature.getInstance(sigAlgo, Utils.TEST_SUITE_PROVIDER_NAME);
        verifying.initVerify(publicKey);
        verifying.update(message);
        assertTrue("Signature verification failed", verifying.verify(signedBytes));
    }

    // Use a non FIPS provider to get a 1024 bits of RSA key.
    @Override
    protected KeyPair generateKeyPair(int keysize) throws Exception {
        KeyPairGenerator rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", Utils.PROVIDER_SunRsaSign);
        rsaKeyPairGen.initialize(keysize);
        return rsaKeyPairGen.generateKeyPair();
    }

    //--------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        junit.textui.TestRunner.run(suite());
    }

    //--------------------------------------------------------------------------
    //
    //
    public static Test suite() {
        TestSuite suite = new TestSuite(TestRSASignatureInteropNonFIPS.class);
        return suite;
    }
}
