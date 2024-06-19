/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class BaseTestDSAKey extends BaseTest {

    // --------------------------------------------------------------------------
    //
    //
    protected KeyPairGenerator dsaKeyPairGen;
    protected KeyFactory dsaKeyFactory;

    // --------------------------------------------------------------------------
    //
    //
    public BaseTestDSAKey(String providerName) {
        super(providerName);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {
        dsaKeyPairGen = KeyPairGenerator.getInstance("DSA", providerName);
        dsaKeyFactory = KeyFactory.getInstance("DSA", providerName);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    // --------------------------------------------------------------------------
    //
    //
    public void testDSAKeyGen_1024() throws Exception {
        try {
            KeyPair dsaKeyPair = generateKeyPair(1024);
            dsaKeyPair.getPublic();
            dsaKeyPair.getPrivate();
        } catch (InvalidParameterException | InvalidKeyException ikex) {
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
    public void testDSAKeyGen_2048() throws Exception {
        KeyPair dsaKeyPair = generateKeyPair(2048);
        dsaKeyPair.getPublic();
        dsaKeyPair.getPrivate();
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testDSAKeyGenFromParams_1024() throws Exception {
        try {
            AlgorithmParameters algParams = generateParameters(1024);
            DSAParameterSpec dsaParameterSpec = algParams
                    .getParameterSpec(DSAParameterSpec.class);
            KeyPair dsaKeyPair = generateKeyPair(dsaParameterSpec);
            dsaKeyPair.getPublic();
            dsaKeyPair.getPrivate();
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
    public void testDSAKeyFactoryCreateFromEncoded_1024() throws Exception {
        try {

            keyFactoryCreateFromEncoded(1024);
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
    public void testDSAKeyFactoryCreateFromEncoded_2048() throws Exception {
        keyFactoryCreateFromEncoded(2048);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testDSAKeyFactoryCreateFromKeySpec_1024() throws Exception {
        try {
            keyFactoryCreateFromKeySpec(1024);
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
    public void testDSAKeyFactoryCreateFromKeySpec_2048() throws Exception {
        keyFactoryCreateFromKeySpec(2048);
    }

    // --------------------------------------------------------------------------
    //
    //
    protected AlgorithmParameters generateParameters(int size) throws Exception {
        AlgorithmParameterGenerator algParmGen = AlgorithmParameterGenerator.getInstance("DSA",
                providerName);
        algParmGen.init(size);
        AlgorithmParameters algParams = algParmGen.generateParameters();
        return algParams;
    }

    // --------------------------------------------------------------------------
    //
    //
    protected KeyPair generateKeyPair(int size) throws Exception {
        dsaKeyPairGen.initialize(size);
        KeyPair keyPair = dsaKeyPairGen.generateKeyPair();

        if (keyPair.getPrivate() == null) {
            fail("DSA Private key is null");
        }

        if (keyPair.getPublic() == null) {
            fail("DSA Public key is null");
        }

        if (!(keyPair.getPrivate() instanceof DSAPrivateKey)) {
            fail("Private key is not a DSAPrivateKey");
        }

        if (!(keyPair.getPublic() instanceof DSAPublicKey)) {
            fail("Private key is not a DSAPublicKey");
        }

        return keyPair;
    }

    // --------------------------------------------------------------------------
    //
    //
    protected KeyPair generateKeyPair(DSAParameterSpec dsaParameterSpec) throws Exception {
        dsaKeyPairGen.initialize(dsaParameterSpec);
        KeyPair keyPair = dsaKeyPairGen.generateKeyPair();

        if (keyPair.getPrivate() == null) {
            fail("DSA Private key is null");
        }

        if (keyPair.getPublic() == null) {
            fail("DSA Public key is null");
        }

        if (!(keyPair.getPrivate() instanceof DSAPrivateKey)) {
            fail("Private key is not a DSAPrivateKey");
        }

        if (!(keyPair.getPublic() instanceof DSAPublicKey)) {
            fail("Private key is not a DSAPublicKey");
        }

        return keyPair;
    }

    // --------------------------------------------------------------------------
    //
    //
    protected void keyFactoryCreateFromEncoded(int size) throws Exception {

        KeyPair dsaKeyPair = generateKeyPair(size);

        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(dsaKeyPair.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(
                dsaKeyPair.getPrivate().getEncoded());

        DSAPublicKey dsaPub = (DSAPublicKey) dsaKeyFactory.generatePublic(x509Spec);
        DSAPrivateKey dsaPriv = (DSAPrivateKey) dsaKeyFactory.generatePrivate(pkcs8Spec);

        if (!Arrays.equals(dsaPub.getEncoded(), dsaKeyPair.getPublic().getEncoded())) {
            fail("DSA public key does not match generated public key");
        }

        if (!Arrays.equals(dsaPriv.getEncoded(), dsaKeyPair.getPrivate().getEncoded())) {
            fail("DSA private key does not match generated public key");
        }
    }

    // --------------------------------------------------------------------------
    //
    //
    protected void keyFactoryCreateFromKeySpec(int size) throws Exception {

        KeyPair dsaKeyPair = generateKeyPair(size);

        DSAPublicKeySpec dsaPubSpec = dsaKeyFactory
                .getKeySpec(dsaKeyPair.getPublic(), DSAPublicKeySpec.class);
        DSAPublicKey dsaPub = (DSAPublicKey) dsaKeyFactory.generatePublic(dsaPubSpec);

        if (!Arrays.equals(dsaPub.getEncoded(), dsaKeyPair.getPublic().getEncoded())) {
            fail("DSA public key does not match generated public key");
        }

        DSAPrivateKeySpec dsaPrivateSpec = dsaKeyFactory
                .getKeySpec(dsaKeyPair.getPrivate(), DSAPrivateKeySpec.class);
        DSAPrivateKey dsaPriv = (DSAPrivateKey) dsaKeyFactory.generatePrivate(dsaPrivateSpec);

        if (!Arrays.equals(dsaPriv.getEncoded(), dsaKeyPair.getPrivate().getEncoded())) {
            fail("DSA private key does not match generated private key");
        }
    }
}
