/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;

public class BaseTestRSATypeCheckDisabled extends BaseTest {
    // --------------------------------------------------------------------------
    //
    //
    static final int DEFAULT_KEY_SIZE = 2048;

    // --------------------------------------------------------------------------
    //
    //
    KeyPairGenerator rsaKeyPairGen;
    KeyPair rsaKeyPair;
    RSAPublicKey rsaPub;
    RSAPrivateCrtKey rsaPriv;

    // --------------------------------------------------------------------------
    //
    //
    public BaseTestRSATypeCheckDisabled(String providerName) {
        super(providerName);
    }

    // --------------------------------------------------------------------------
    //
    //
    protected void setUp() throws Exception {
        rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", providerName);
        rsaKeyPairGen.initialize(DEFAULT_KEY_SIZE, null);
        rsaKeyPair = rsaKeyPairGen.generateKeyPair();
        rsaPub = (RSAPublicKey) rsaKeyPair.getPublic();
        rsaPriv = (RSAPrivateCrtKey) rsaKeyPair.getPrivate();
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testPrivateKeyEncrypt() throws Exception {
        Cipher cp = Cipher.getInstance("RSA", providerName);
        cp.init(Cipher.ENCRYPT_MODE, rsaPriv);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testPublicKeyDecrypt() throws Exception {
        Cipher cp = Cipher.getInstance("RSA", providerName);
        cp.init(Cipher.DECRYPT_MODE, rsaPub);
    }
}

