/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import sun.security.util.InternalPrivateKey;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class BaseTestXDHInterop extends BaseTestJunit5Interop {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();
    // The below strings are base64 encoded X25519/X448 public/private keys generated using OpenJDK
    String openJDK_public_X25519 = "MCwwBwYDK2VuBQADIQA4HbX7tMVhQEZZcJC+1ds9d9C2CVdS33Yu/fE1aDlUHQ==";
    String openJDK_private_X25519 = "MC4CAQAwBwYDK2VuBQAEIH5jrfhGLlhemXDjaHm/kjHcHikVr16pXv1je2GJpc9+";
    String openJDK_public_X448 = "MEQwBwYDK2VvBQADOQC+jxO+a0rKrAPolPsmmsipDDtobNXjxrzap2Rde9rgJe7/fsbJ+j1+YlgJp11IGFwLxsslJYTTww==";
    String openJDK_private_X448 = "MEYCAQAwBwYDK2VvBQAEOOJFsgLYxgAIEWuN1FLAGWDzGQRSataAbPLDc1wv5aky4T8hevyWbYdhggc1OCcqQ93gY8rqVTDb";
    // OpenJDK does not currently support FFDHE hence interop testing for FFDHE is not possible

    @Test
    public void testCreateKeyPairXDHGenParamImportCalculatePublic() throws Exception {
        if (!"BC".equals(getInteropProviderName())) {
            doCreateKeyPairXDHGenParamImportCalculatePublic(getProviderName(), getInteropProviderName());
            doCreateKeyPairXDHGenParamImportCalculatePublic(getInteropProviderName(), getProviderName());
        }
        
    }

    private void doCreateKeyPairXDHGenParamImportCalculatePublic(String generateProviderName,
            String importProviderName) throws Exception {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("XDH", generateProviderName);

        keyPairGen.initialize(255);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Recreate private key from encoding.
        byte[] privKeyBytes = privateKey.getEncoded();
        KeyFactory keyFactory = KeyFactory.getInstance("XDH", importProviderName);
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);
        privateKey = keyFactory.generatePrivate(privateKeySpec);

        // Get public key bytes from private.
        byte[] calculatedPublicKey = ((InternalPrivateKey) privateKey).calculatePublicKey().getEncoded();

        // Get public key bytes from original public key.
        byte[] publicKeyBytes = publicKey.getEncoded();

        System.out.println("---- Comparing XDH public key from KeyPair vs calculated from private key ----");
        System.out.println("XDH public key from Keypair from " + generateProviderName + ": "
                + BaseUtils.bytesToHex(publicKeyBytes));
        System.out.println("XDH public key from calculatePublicKey() from " + importProviderName + ": "
                + BaseUtils.bytesToHex(calculatedPublicKey));

        // The original and calculated public keys should be the same
        assertArrayEquals(calculatedPublicKey, publicKeyBytes);
    }

    @Test
    public void testXDHInterop_X25519_OpenJDK() throws Exception {
        byte[] openJDK_public_bytes = Base64.getDecoder().decode(openJDK_public_X25519);
        byte[] openJDK_private_bytes = Base64.getDecoder().decode(openJDK_private_X25519);
        buildOpenJCEPlusKeys("X25519", openJDK_public_bytes, openJDK_private_bytes, getProviderName());
    }

    @Test
    public void testXDHMulti_x448_OpenJDK() throws Exception {
        byte[] openJDK_public_bytes = Base64.getDecoder().decode(openJDK_public_X448);
        byte[] openJDK_private_bytes = Base64.getDecoder().decode(openJDK_private_X448);
        buildOpenJCEPlusKeys("X448", openJDK_public_bytes, openJDK_private_bytes, getProviderName());
    }

    @Test
    public void testXDH_X448_KeyGeneration() throws Exception {
        System.out.println("Testing XDH key generated with provider " + getInteropProviderName() + " using provider " + getProviderName());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH", getInteropProviderName());
        AlgorithmParameterSpec paramSpec = new NamedParameterSpec("X448");
        kpg.initialize(paramSpec);
        KeyPair kp = kpg.generateKeyPair();

        buildOpenJCEPlusKeys("X448", kp.getPublic().getEncoded(), kp.getPrivate().getEncoded(), getProviderName());
    }

    @Test
    public void testXDH_X25519_KeyGeneration() throws Exception {
        System.out.println("Testing XDH key generated with provider " + getInteropProviderName() + " using provider " + getProviderName());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH", getInteropProviderName());
        AlgorithmParameterSpec paramSpec = new NamedParameterSpec("X25519");
        kpg.initialize(paramSpec);
        KeyPair kp = kpg.generateKeyPair();

        buildOpenJCEPlusKeys("X25519", kp.getPublic().getEncoded(), kp.getPrivate().getEncoded(), getProviderName());
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
