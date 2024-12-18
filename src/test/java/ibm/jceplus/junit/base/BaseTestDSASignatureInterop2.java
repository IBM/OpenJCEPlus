/*
 * Copyright IBM Corp. 2023, 2024
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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestDSASignatureInterop2 extends BaseTestSignatureInterop {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    @Test
    public void testSHA3_2244withDSA_1024() throws Exception {
        try {
            KeyPair keyPairFromProvider = generateKeyPair(1024);
            doSignVerify("SHA3-224withDSA", origMsg, keyPairFromProvider.getPrivate(),
                    keyPairFromProvider.getPublic());

            KeyPair keyPairFromInteropProvider = generateKeyPairFromInteropProvider(1024);
            doSignVerify("SHA3-224withDSA", origMsg, keyPairFromInteropProvider.getPrivate(),
                    keyPairFromInteropProvider.getPublic());
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_256withDSA_1024() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(1024);
            doSignVerify("SHA3-256withDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_384withDSA_1024() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(1024);
            doSignVerify("SHA3-384withDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_512withDSA_1024() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(1024);
            doSignVerify("SHA3-512withDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_224withDSA_2048() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(2048);
            doSignVerify("SHA3-224withDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_256withDSA_2048() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(2048);
            doSignVerify("SHA3-256withDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_384withDSA_2048() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(2048);
            doSignVerify("SHA3-384withDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_512withDSA_2048() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(2048);
            doSignVerify("SHA3-512withDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void test_encoding() throws Exception {
        test_dsa_encoded(getProviderName(), getProviderName());
        test_dsa_encoded(getInteropProviderName(), getInteropProviderName());
        test_dsa_encoded(getProviderName(), getInteropProviderName());
        test_dsa_encoded(getInteropProviderName(), getProviderName());
    }

    void test_dsa_encoded(String providerNameX, String providerNameY) throws Exception {

        System.out.println("providerNameX = " + providerNameX + " providerNameY=" + providerNameY);

        KeyFactory dsaKeyFactoryX = KeyFactory.getInstance("DSA", providerNameX);

        KeyPair dsaKeyPairX = generateKeyPair(2048);

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


    protected KeyPair generateKeyPair(int keysize) throws Exception {
        KeyPairGenerator dsaKeyPairGen = KeyPairGenerator.getInstance("DSA", getProviderName());
        dsaKeyPairGen.initialize(keysize);
        return dsaKeyPairGen.generateKeyPair();
    }

    protected KeyPair generateKeyPairFromInteropProvider(int keysize) throws Exception {
        KeyPairGenerator dsaKeyPairGen = KeyPairGenerator.getInstance("DSA", getInteropProviderName());
        dsaKeyPairGen.initialize(keysize);
        return dsaKeyPairGen.generateKeyPair();
    }
}
