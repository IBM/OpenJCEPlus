/*
 * Copyright IBM Corp. 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import ibm.security.internal.spec.CCMParameterSpec;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

public class BaseTestIsAssignableFromOrder extends BaseTestJunit5 {

    @Test
    public void testIsAssignableFromOrder() throws Exception {

        // AlgorithmParameters
        testAlgSpec("AES", new IvParameterSpec(new byte[16]));
        testAlgSpec("CCM", new CCMParameterSpec(128, new byte[12]));
        testAlgSpec("ChaCha20-Poly1305", new IvParameterSpec(new byte[12]));
        testAlgSpec("DESede", new IvParameterSpec(new byte[8]));
        testAlgSpec("DH", new DHParameterSpec(BigInteger.ONE, BigInteger.TWO));
        testAlgSpec("DSA", new DSAParameterSpec(BigInteger.ONE, BigInteger.TWO, BigInteger.ONE));
        testAlgSpec("GCM", new GCMParameterSpec(96, new byte[16]));
        testAlgSpec("OAEP", new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
        testAlgSpec("RSAPSS", new PSSParameterSpec("SHA256", "MGF1", MGF1ParameterSpec.SHA256, 20, 1));

        // SecretKeyFactory
        testSecretKeySpec("AES", new SecretKeySpec(new byte[16], "AES"), SecretKeySpec.class);
        testSecretKeySpec("DESede", new SecretKeySpec(new byte[24], "DESede"), DESedeKeySpec.class);

        // KeyFactory DH, DSA, EC, RSA, XDH
        testKeySpec("DH", 1024, DHPublicKeySpec.class, DHPrivateKeySpec.class);
        testKeySpec("DSA", 1024, DSAPublicKeySpec.class, DSAPrivateKeySpec.class);
        testKeySpec("EC", 521, ECPublicKeySpec.class, ECPrivateKeySpec.class);
        testKeySpec("RSA", 1024, RSAPublicKeySpec.class, RSAPrivateKeySpec.class);
        testKeySpec("XDH", 255, XECPublicKeySpec.class, XECPrivateKeySpec.class);
    }

    // Test Algorithm Parameters Spec
    private void testAlgSpec(String algorithm, AlgorithmParameterSpec spec) throws Exception {
        System.out.println("test AlgorithmParametersSpec: " + algorithm);

        AlgorithmParameters ap1 = AlgorithmParameters.getInstance(algorithm, getProviderName());
        ap1.init(spec);

        AlgorithmParameters ap2 = AlgorithmParameters.getInstance(algorithm, getProviderName());
        ap2.init(ap1.getEncoded());

        List<Class<? extends AlgorithmParameterSpec>> classes = new ArrayList<>();
        classes.add(spec.getClass());
        classes.add(AlgorithmParameterSpec.class);

        for (Class<? extends AlgorithmParameterSpec> c : classes) {
            ap1.getParameterSpec(c);
            ap2.getParameterSpec(c);
        }
    }

    // Test Secret Key Spec
    private void testSecretKeySpec(String algorithm, KeySpec spec, Class<?> clazz)
            throws Exception {
        System.out.println("test SecretKeySpec: " + algorithm);

        SecretKeyFactory kf = SecretKeyFactory.getInstance(algorithm, getProviderName());
        SecretKey key = kf.generateSecret(spec);

        kf.getKeySpec(key, KeySpec.class);
        kf.getKeySpec(key, clazz);
    }

    // Test Public and Private Key Spec
    private void testKeySpec(String algorithm, int size, Class<? extends KeySpec> clazz1, Class<? extends KeySpec> clazz2)
            throws Exception {
        System.out.println("test KeySpec: " + algorithm);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, getProviderName());
        kpg.initialize(size);
        KeyPair kp = kpg.generateKeyPair();

        PublicKey pubk = kp.getPublic();
        PrivateKey prvk = kp.getPrivate();

        byte[] encodedpubk = pubk.getEncoded();
        byte[] encodedprvk = prvk.getEncoded();

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedpubk);
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedprvk);

        KeyFactory kf = KeyFactory.getInstance(algorithm, getProviderName());
        PublicKey publicKey = kf.generatePublic(publicKeySpec);
        PrivateKey privateKey = kf.generatePrivate(privateKeySpec);

        kf.getKeySpec(publicKey, KeySpec.class);
        kf.getKeySpec(publicKey, clazz1);

        kf.getKeySpec(privateKey, KeySpec.class);
        kf.getKeySpec(privateKey, clazz2);
    }
}
