/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class BaseTestXDHInterop extends BaseTestInterop {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();
    // The below strings are base64 encoded X25519/X448 public/private keys generated using OpenJDK
    String openJDK_public_X25519 = "MCwwBwYDK2VuBQADIQA4HbX7tMVhQEZZcJC+1ds9d9C2CVdS33Yu/fE1aDlUHQ==";
    String openJDK_private_X25519 = "MC4CAQAwBwYDK2VuBQAEIH5jrfhGLlhemXDjaHm/kjHcHikVr16pXv1je2GJpc9+";
    String openJDK_public_X448 = "MEQwBwYDK2VvBQADOQC+jxO+a0rKrAPolPsmmsipDDtobNXjxrzap2Rde9rgJe7/fsbJ+j1+YlgJp11IGFwLxsslJYTTww==";
    String openJDK_private_X448 = "MEYCAQAwBwYDK2VvBQAEOOJFsgLYxgAIEWuN1FLAGWDzGQRSataAbPLDc1wv5aky4T8hevyWbYdhggc1OCcqQ93gY8rqVTDb";
    // OpenJDK does not currently support FFDHE hence interop testing for FFDHE is not possible

    public BaseTestXDHInterop(String providerName, String interopProviderName) {
        super(providerName, interopProviderName);
    }

    public void setUp() throws Exception {}

    public void tearDown() throws Exception {}

    public void testXDHInterop_X25519_OpenJDK() throws Exception {
        byte[] openJDK_public_bytes = Base64.getDecoder().decode(openJDK_public_X25519);
        byte[] openJDK_private_bytes = Base64.getDecoder().decode(openJDK_private_X25519);
        buildOpenJCEPlusKeys("X25519", openJDK_public_bytes, openJDK_private_bytes, providerName);
    }

    public void testXDHMulti_x448_OpenJDK() throws Exception {
        byte[] openJDK_public_bytes = Base64.getDecoder().decode(openJDK_public_X448);
        byte[] openJDK_private_bytes = Base64.getDecoder().decode(openJDK_private_X448);
        buildOpenJCEPlusKeys("X448", openJDK_public_bytes, openJDK_private_bytes, providerName);
    }

    public void testXDH_X448_KeyGeneration() throws Exception {
        System.out.println("Testing XDH key generated with provider " + interopProviderName + " using provider " + providerName);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH", interopProviderName);
        AlgorithmParameterSpec paramSpec = new NamedParameterSpec("X448");
        kpg.initialize(paramSpec);
        KeyPair kp = kpg.generateKeyPair();

        buildOpenJCEPlusKeys("X448", kp.getPublic().getEncoded(), kp.getPrivate().getEncoded(), providerName);
    }

    public void testXDH_X25519_KeyGeneration() throws Exception {
        System.out.println("Testing XDH key generated with provider " + interopProviderName + " using provider " + providerName);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH", interopProviderName);
        AlgorithmParameterSpec paramSpec = new NamedParameterSpec("X25519");
        kpg.initialize(paramSpec);
        KeyPair kp = kpg.generateKeyPair();

        buildOpenJCEPlusKeys("X25519", kp.getPublic().getEncoded(), kp.getPrivate().getEncoded(), providerName);
    }

    void buildOpenJCEPlusKeys(String idString, byte[] publicKeyBytes, byte[] privateKeyBytes,
            String provider) throws Exception {
        //final String methodName = "buildOpenJCEPlusKeys" + "_" + idString;

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("XDH", provider);
        keyFactory.generatePublic(publicKeySpec);
        keyFactory.generatePrivate(privateKeySpec);
    }
}
