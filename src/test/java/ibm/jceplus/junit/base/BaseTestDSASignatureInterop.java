/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class BaseTestDSASignatureInterop extends BaseTestSignatureInterop {

    // --------------------------------------------------------------------------
    //
    //
    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    // --------------------------------------------------------------------------
    //
    //
    public BaseTestDSASignatureInterop(String providerName, String interopProviderName) {
        super(providerName, interopProviderName);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {}

    // --------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA1withDSA_1024() throws Exception {
        KeyPair keyPair = null;
        try {
            keyPair = generateKeyPair(1024);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: DSA for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
        try {
            doSignVerify("SHA1withDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA224withDSA_1024() throws Exception {
        KeyPair keyPair = null;
        try {
            keyPair = generateKeyPair(1024);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: DSA for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
        try {
            doSignVerify("SHA224withDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA256withDSA_1024() throws Exception {
        KeyPair keyPair = null;
        try {
            keyPair = generateKeyPair(1024);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: DSA for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
        try {
            doSignVerify("SHA256withDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testNONEwithDSA_2048_hash20() throws Exception {
        KeyPair keyPair = null;
        try {
            keyPair = generateKeyPair(2048);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: DSA for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
        byte[] sslHash = Arrays.copyOf(origMsg, 20);
        doSignVerify("NONEwithDSA", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void test_encoding() throws Exception {
        test_dsa_encoded(providerName, providerName);
        test_dsa_encoded(interopProviderName, interopProviderName);
        test_dsa_encoded(providerName, interopProviderName);
        test_dsa_encoded(interopProviderName, providerName);
    }

    void test_dsa_encoded(String providerNameX, String providerNameY) throws Exception {

        System.out.println("providerNameX = " + providerNameX + " providerNameY=" + providerNameY);

        KeyFactory dsaKeyFactoryX = KeyFactory.getInstance("DSA", providerNameX);

        KeyPair dsaKeyPairX = null;
        try {
            dsaKeyPairX = generateKeyPair(2048);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: DSA for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }

        X509EncodedKeySpec x509SpecX = new X509EncodedKeySpec(dsaKeyPairX.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8SpecX = new PKCS8EncodedKeySpec(
                dsaKeyPairX.getPrivate().getEncoded());

        DSAPublicKey dsaPubX = (DSAPublicKey) dsaKeyFactoryX.generatePublic(x509SpecX);
        DSAPrivateKey dsaPrivX = (DSAPrivateKey) dsaKeyFactoryX.generatePrivate(pkcs8SpecX);

        if (!Arrays.equals(dsaPubX.getEncoded(), dsaKeyPairX.getPublic().getEncoded())) {
            fail("DSA public key does not match generated public key");
        }

        if (!Arrays.equals(dsaPrivX.getEncoded(), dsaKeyPairX.getPrivate().getEncoded())) {
            fail("DSA private key does not match generated public key");
        }

        KeyFactory dsaKeyFactoryY = KeyFactory.getInstance("DSA", providerNameY);

        X509EncodedKeySpec x509KeySpecY = new X509EncodedKeySpec(
                dsaKeyPairX.getPublic().getEncoded());
        PublicKey dsaPubY = dsaKeyFactoryY.generatePublic(x509KeySpecY);

        PrivateKey dsaPrivY = dsaKeyFactoryY
                .generatePrivate(new PKCS8EncodedKeySpec(dsaKeyPairX.getPrivate().getEncoded()));

        if (!Arrays.equals(dsaPubX.getEncoded(), dsaPubY.getEncoded())) {
            fail("DSA public key from provider X  " + providerNameX
                    + " does not match public key encoding from provider" + providerNameY);
        }

        if (!Arrays.equals(dsaPrivX.getEncoded(), dsaPrivY.getEncoded())) {
            fail("DSA private key from provider X  " + providerNameX
                    + " does not match private key encoding from provider" + providerNameY);
        }

        if (!Arrays.equals(dsaPrivY.getEncoded(), dsaKeyPairX.getPrivate().getEncoded())) {
            fail("DSA private key does not match private public key");
        }

        if (!Arrays.equals(dsaPrivY.getEncoded(), dsaKeyPairX.getPrivate().getEncoded())) {
            fail("DSA private key does not match generated prviate key");
        }

        if (!Arrays.equals(dsaPubY.getEncoded(), dsaKeyPairX.getPublic().getEncoded())) {
            fail("DSA private key does not match generated prviate key");
        }

    }

    // --------------------------------------------------------------------------
    //
    //
    protected KeyPair generateKeyPair(int keysize) throws Exception {
        KeyPairGenerator dsaKeyPairGen = KeyPairGenerator.getInstance("DSA", providerName);
        dsaKeyPairGen.initialize(keysize);
        return dsaKeyPairGen.generateKeyPair();
    }
}
