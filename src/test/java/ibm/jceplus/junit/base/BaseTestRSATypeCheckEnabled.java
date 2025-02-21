/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestRSATypeCheckEnabled extends BaseTestJunit5 {

    static final int DEFAULT_KEY_SIZE = 2048;


    KeyPairGenerator rsaKeyPairGen;
    KeyPair rsaKeyPair;
    RSAPublicKey rsaPub;
    RSAPrivateCrtKey rsaPriv;

    @BeforeEach
    public void setUp() throws Exception {
        rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", getProviderName());
        rsaKeyPairGen.initialize(DEFAULT_KEY_SIZE, null);
        rsaKeyPair = rsaKeyPairGen.generateKeyPair();
        rsaPub = (RSAPublicKey) rsaKeyPair.getPublic();
        rsaPriv = (RSAPrivateCrtKey) rsaKeyPair.getPrivate();
    }

    @Test
    public void testPrivateKeyEncrypt() throws Exception {
        try {
            Cipher cp = Cipher.getInstance("RSA", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, rsaPriv);
            fail("Expected InvalidKeyException did not occur");
        } catch (InvalidKeyException ike) {
            assertTrue(true);
        }
    }

    @Test
    public void testPublicKeyDecrypt() throws Exception {
        try {
            Cipher cp = Cipher.getInstance("RSA", getProviderName());
            cp.init(Cipher.DECRYPT_MODE, rsaPub);
            fail("Expected InvalidKeyException did not occur");
        } catch (InvalidKeyException ike) {
            assertTrue(true);
        }
    }
}
