/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class BaseTestKeyEncodings extends BaseTestJunit5 {

    @Test
    void testDSAKeyFormatAndEncoding() throws Exception {
        // DSA key pair generation not supported by OpenJCEPlusFIPS, skip this test.
        if (getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
            return;
        }

        AlgorithmParameterGenerator paramGen224 = AlgorithmParameterGenerator.getInstance("DSA", getProviderName());
        paramGen224.init(2048);
        AlgorithmParameters params224 = paramGen224.generateParameters();
        DSAParameterSpec spec224 = params224.getParameterSpec(DSAParameterSpec.class);
        KeyPairGenerator dsaKeyGen = KeyPairGenerator.getInstance("DSA", getProviderName());
        dsaKeyGen.initialize(spec224);
        KeyPair dsaKeyPair = dsaKeyGen.generateKeyPair();
        DSAPublicKey dsaPublicKey = (DSAPublicKey) dsaKeyPair.getPublic();
        DSAPrivateKey dsaPrivateKey = (DSAPrivateKey) dsaKeyPair.getPrivate();

        // Lets print and test encoding format.
        byte[] publicKeyEncoded = dsaPublicKey.getEncoded();
        byte[] privateKeyEncoded = dsaPrivateKey.getEncoded();
        System.out.println("DSA Public Key Encoding: " + BaseUtils.bytesToHex(publicKeyEncoded));
        System.out.println("DSA Private Key Encoding: " + BaseUtils.bytesToHex(privateKeyEncoded));
        assertNotNull(publicKeyEncoded);
        assertNotNull(privateKeyEncoded);

        // Validate algorithm and format.
        assertEquals("DSA", dsaPublicKey.getAlgorithm());
        assertEquals("DSA", dsaPrivateKey.getAlgorithm());
        assertEquals("X.509", dsaPublicKey.getFormat());
        assertEquals("PKCS#8", dsaPrivateKey.getFormat());
    }

    @Test
    void testRSAKeyFormatAndEncoding() throws Exception {
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA", getProviderName());
        rsaKeyGen.initialize(2048);
        KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        // Lets print and test encoding format.
        byte[] publicKeyEncoded = rsaPublicKey.getEncoded();
        byte[] privateKeyEncoded = rsaPrivateKey.getEncoded();
        System.out.println("RSA Public Key Encoding: " + BaseUtils.bytesToHex(publicKeyEncoded));
        System.out.println("RSA Private Key Encoding: " + BaseUtils.bytesToHex(privateKeyEncoded));
        assertNotNull(publicKeyEncoded);
        assertNotNull(privateKeyEncoded);

        // Validate algorithm and format.
        assertEquals("RSA", rsaPublicKey.getAlgorithm());
        assertEquals("RSA", rsaPrivateKey.getAlgorithm());
        assertEquals("X.509", rsaPublicKey.getFormat());
        assertEquals("PKCS#8", rsaPrivateKey.getFormat());
    }

    @Test
    void testEdDSAKeyFormatAndEncoding() throws Exception {

        // EdDSA key pair generation not supported by OpenJCEPlusFIPS, skip this test.
        if (getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
            return;
        }

        KeyPairGenerator eddsaKeyGen = KeyPairGenerator.getInstance("EdDSA", getProviderName());
        eddsaKeyGen.initialize(new NamedParameterSpec("Ed25519"));
        KeyPair eddsaKeyPair = eddsaKeyGen.generateKeyPair();
        PublicKey eddsaPublicKey = eddsaKeyPair.getPublic();
        PrivateKey eddsaPrivateKey = eddsaKeyPair.getPrivate();

        // Lets print and test encoding format.
        byte[] publicKeyEncoded = eddsaPublicKey.getEncoded();
        byte[] privateKeyEncoded = eddsaPrivateKey.getEncoded();
        System.out.println("EdDSA Public Key Encoding: " + BaseUtils.bytesToHex(publicKeyEncoded));
        System.out.println("EdDSA Private Key Encoding: " + BaseUtils.bytesToHex(privateKeyEncoded));
        assertNotNull(publicKeyEncoded);
        assertNotNull(privateKeyEncoded);

        // Validate algorithm and format.
        assertEquals("EdDSA", eddsaPublicKey.getAlgorithm());
        assertEquals("EdDSA", eddsaPrivateKey.getAlgorithm());
        assertEquals("X.509", eddsaPublicKey.getFormat());
        assertEquals("PKCS#8", eddsaPrivateKey.getFormat());
    }

    @Test
    void testXDHKeyFormatAndEncoding() throws Exception {

        // XDH key pair generation not supported by OpenJCEPlusFIPS, skip this test.
        if (getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
            return;
        }

        KeyPairGenerator xdhKeyGen = KeyPairGenerator.getInstance("XDH", getProviderName());
        xdhKeyGen.initialize(new NamedParameterSpec("X25519"));
        KeyPair xdhKeyPair = xdhKeyGen.generateKeyPair();
        PublicKey xdhPublicKey = xdhKeyPair.getPublic();
        PrivateKey xdhPrivateKey = xdhKeyPair.getPrivate();

        // Lets print and test encoding format.
        byte[] publicKeyEncoded = xdhPublicKey.getEncoded();
        byte[] privateKeyEncoded = xdhPrivateKey.getEncoded();
        System.out.println("XDH Public Key Encoding: " + BaseUtils.bytesToHex(publicKeyEncoded));
        System.out.println("XDH Private Key Encoding: " + BaseUtils.bytesToHex(privateKeyEncoded));
        assertNotNull(publicKeyEncoded);
        assertNotNull(privateKeyEncoded);

        // Validate algorithm and format.
        assertEquals("XDH", xdhPublicKey.getAlgorithm());
        assertEquals("XDH", xdhPrivateKey.getAlgorithm());
        assertEquals("X.509", xdhPublicKey.getFormat());
        assertEquals("PKCS#8", xdhPrivateKey.getFormat());
    }

    @Test
    void testECKeyGenerationDifferentCurves() throws Exception {
        String[] curves = {"secp256r1", "secp384r1", "secp521r1"};

        for (String curveName : curves) {
            System.out.println("Test curve: " + curveName);
            KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC", getProviderName());
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
            ecKeyGen.initialize(ecSpec);
            KeyPair ecKeyPair = ecKeyGen.generateKeyPair();
            ECPublicKey ecPublicKey = (ECPublicKey) ecKeyPair.getPublic();
            ECPrivateKey ecPrivateKey = (ECPrivateKey) ecKeyPair.getPrivate();

            // Lets print and test encoding format.
            byte[] publicKeyEncoded = ecPublicKey.getEncoded();
            byte[] privateKeyEncoded = ecPrivateKey.getEncoded();
            System.out.println("EC Public Key Encoding (" + curveName + "): " + BaseUtils.bytesToHex(publicKeyEncoded));
            System.out.println("EC Private Key Encoding (" + curveName + "): " + BaseUtils.bytesToHex(privateKeyEncoded));
            assertNotNull(publicKeyEncoded);
            assertNotNull(privateKeyEncoded);


            // Validate algorithm and format.
            assertEquals("EC", ecPublicKey.getAlgorithm());
            assertEquals("EC", ecPrivateKey.getAlgorithm());
            assertEquals("X.509", ecPublicKey.getFormat());
            assertEquals("PKCS#8", ecPrivateKey.getFormat());
        }
    }
}
