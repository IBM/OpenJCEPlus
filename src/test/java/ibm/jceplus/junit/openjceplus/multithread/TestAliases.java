/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplus.multithread;

import ibm.jceplus.junit.base.BaseTestJunit5;
import ibm.jceplus.junit.openjceplus.Utils;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
public class TestAliases extends BaseTestJunit5 {

    @BeforeAll
    public void setUp() {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    @Test
    public void testAlgParams_3DES() throws Exception {
        AlgorithmParameters.getInstance("3DES", getProviderName());
    }

    @Test
    public void testAlgParams_AESGCM() throws Exception {
        AlgorithmParameters.getInstance("AESGCM", getProviderName());
    }

    @Test
    public void testAlgParamGen_AESGCM() throws Exception {
        AlgorithmParameterGenerator.getInstance("AESGCM", getProviderName());
    }

    @Test
    public void testCipher_3DES() throws Exception {
        Cipher.getInstance("3DES", getProviderName());
    }

    @Test
    public void testKeyFactory_DSAKeyFactory() throws Exception {
        KeyFactory.getInstance("DSAKeyFactory", getProviderName());
    }

    @Test
    public void testKeyGen_3DES() throws Exception {
        KeyGenerator.getInstance("3DES", getProviderName());
    }

    @Test
    public void testKeyGen_HMACwithSHA1() throws Exception {
        KeyGenerator.getInstance("HMACwithSHA1", getProviderName());
    }

    @Test
    public void testKeyGen_HMACwithSHA224() throws Exception {
        KeyGenerator.getInstance("HMACwithSHA224", getProviderName());
    }

    @Test
    public void testKeyGen_HMACwithSHA256() throws Exception {
        KeyGenerator.getInstance("HMACwithSHA256", getProviderName());
    }

    @Test
    public void testKeyGen_HMACwithSHA384() throws Exception {
        KeyGenerator.getInstance("HMACwithSHA384", getProviderName());
    }

    @Test
    public void testKeyGen_HMACwithSHA512() throws Exception {
        KeyGenerator.getInstance("HMACwithSHA512", getProviderName());
    }

    @Test
    public void testKeyPairGen_OID_1_3_14_3_2_12() throws Exception {
        KeyPairGenerator.getInstance("OID.1.3.14.3.2.12", getProviderName());
    }

    //public void testKeyStore_PKCS12KS() throws Exception {
    //    KeyStore.getInstance("PKCS12KS", getProviderName());
    //}

    @Test
    public void testMac_HMACwithSHA1() throws Exception {
        Mac.getInstance("HMACwithSHA1", getProviderName());
    }

    @Test
    public void testMac_HMACwithSHA224() throws Exception {
        Mac.getInstance("HMACwithSHA224", getProviderName());
    }

    @Test
    public void testMac_HMACwithSHA256() throws Exception {
        Mac.getInstance("HMACwithSHA256", getProviderName());
    }

    @Test
    public void testMac_HMACwithSHA384() throws Exception {
        Mac.getInstance("HMACwithSHA384", getProviderName());
    }

    @Test
    public void testMac_HMACwithSHA512() throws Exception {
        Mac.getInstance("HMACwithSHA512", getProviderName());
    }

    @Test
    public void testMessageDigest_SHA224() throws Exception {
        MessageDigest.getInstance("SHA224", getProviderName());
    }

    @Test
    public void testMessageDigest_SHA2() throws Exception {
        MessageDigest.getInstance("SHA2", getProviderName());
    }

    @Test
    public void testMessageDigest_SHA_2() throws Exception {
        MessageDigest.getInstance("SHA-2", getProviderName());
    }

    @Test
    public void testMessageDigest_SHA256() throws Exception {
        MessageDigest.getInstance("SHA256", getProviderName());
    }

    @Test
    public void testMessageDigest_SHA3() throws Exception {
        MessageDigest.getInstance("SHA3", getProviderName());
    }

    @Test
    public void testMessageDigest_SHA_3() throws Exception {
        MessageDigest.getInstance("SHA-3", getProviderName());
    }

    @Test
    public void testMessageDigest_SHA384() throws Exception {
        MessageDigest.getInstance("SHA384", getProviderName());
    }

    @Test
    public void testMessageDigest_SHA5() throws Exception {
        MessageDigest.getInstance("SHA5", getProviderName());
    }

    @Test
    public void testMessageDigest_SHA_5() throws Exception {
        MessageDigest.getInstance("SHA-5", getProviderName());
    }

    @Test
    public void testMessageDigest_SHA512() throws Exception {
        MessageDigest.getInstance("SHA512", getProviderName());
    }

    @Test
    public void testSecretKeyFactory_3DES() throws Exception {
        SecretKeyFactory.getInstance("3DES", getProviderName());
    }

    @Test
    public void testSecureRandom_SHA2DRBG() throws Exception {
        SecureRandom.getInstance("SHA2DRBG", getProviderName());
    }

    @Test
    public void testSecureRandom_SHA5DRBG() throws Exception {
        SecureRandom.getInstance("SHA5DRBG", getProviderName());
    }

    @Test
    public void testSignature_SHA_1withDSA() throws Exception {
        Signature.getInstance("SHA-1withDSA", getProviderName());
    }

    @Test
    public void testSignature_SHA_1_DSA() throws Exception {
        Signature.getInstance("SHA-1/DSA", getProviderName());
    }

    @Test
    public void testSignature_SHA1_DSA() throws Exception {
        Signature.getInstance("SHA1/DSA", getProviderName());
    }

    @Test
    public void testSignature_SHA_DSA() throws Exception {
        Signature.getInstance("SHA/DSA", getProviderName());
    }

    @Test
    public void testSignature_DSS() throws Exception {
        Signature.getInstance("DSS", getProviderName());
    }

    @Test
    public void testSignature_SHAwithDSA() throws Exception {
        Signature.getInstance("SHAwithDSA", getProviderName());
    }

    @Test
    public void testSignature_DSAWithSHA1() throws Exception {
        Signature.getInstance("DSAWithSHA1", getProviderName());
    }

    @Test
    public void testSignature_OID_1_3_14_3_2_13() throws Exception {
        Signature.getInstance("OID.1.3.14.3.2.13", getProviderName());
    }

    @Test
    public void testSignature_OID_1_3_14_3_2_27() throws Exception {
        Signature.getInstance("OID.1.3.14.3.2.27", getProviderName());
    }

    @Test
    public void testSignature_SHA_224withDSA() throws Exception {
        Signature.getInstance("SHA-224withDSA", getProviderName());
    }

    @Test
    public void testSignature_SHA_224_DSA() throws Exception {
        Signature.getInstance("SHA-224/DSA", getProviderName());
    }

    @Test
    public void testSignature_SHA224_DSA() throws Exception {
        Signature.getInstance("SHA224/DSA", getProviderName());
    }

    @Test
    public void testSignature_SHA2withDSA() throws Exception {
        Signature.getInstance("SHA2withDSA", getProviderName());
    }

    @Test
    public void testSignature_SHA_2withDSA() throws Exception {
        Signature.getInstance("SHA-2withDSA", getProviderName());
    }

    @Test
    public void testSignature_SHA_256withDSA() throws Exception {
        Signature.getInstance("SHA-256withDSA", getProviderName());
    }

    @Test
    public void testSignature_SHA_2_DSA() throws Exception {
        Signature.getInstance("SHA-2/DSA", getProviderName());
    }

    @Test
    public void testSignature_SHA2_DSA() throws Exception {
        Signature.getInstance("SHA2/DSA", getProviderName());
    }

    @Test
    public void testSignature_SHAwithECDSA() throws Exception {
        Signature.getInstance("SHAwithECDSA", getProviderName());
    }

    @Test
    public void testSignature_SHA_1withECDSA() throws Exception {
        Signature.getInstance("SHA-1withECDSA", getProviderName());
    }

    @Test
    public void testSignature_SHA_ECDSA() throws Exception {
        Signature.getInstance("SHA/ECDSA", getProviderName());
    }

    @Test
    public void testSignature_SHA_1_ECDSA() throws Exception {
        Signature.getInstance("SHA-1/ECDSA", getProviderName());
    }

    @Test
    public void testSignature_SHA224_ECDSA() throws Exception {
        Signature.getInstance("SHA224/ECDSA", getProviderName());
    }

    @Test
    public void testSignature_SHA2withECDSA() throws Exception {
        Signature.getInstance("SHA2withECDSA", getProviderName());
    }

    @Test
    public void testSignature_SHA2_ECDSA() throws Exception {
        Signature.getInstance("SHA2/ECDSA", getProviderName());
    }

    @Test
    public void testSignature_SHA3withECDSA() throws Exception {
        Signature.getInstance("SHA3withECDSA", getProviderName());
    }

    @Test
    public void testSignature_SHA3_ECDSA() throws Exception {
        Signature.getInstance("SHA3/ECDSA", getProviderName());
    }

    @Test
    public void testSignature_SHA5withECDSA() throws Exception {
        Signature.getInstance("SHA5withECDSA", getProviderName());
    }

    @Test
    public void testSignature_SHA5_ECDSA() throws Exception {
        Signature.getInstance("SHA5/ECDSA", getProviderName());
    }

    @Test
    public void testSignature_SHA_1withRSA() throws Exception {
        Signature.getInstance("SHA-1withRSA", getProviderName());
    }

    @Test
    public void testSignature_SHAwithRSA() throws Exception {
        Signature.getInstance("SHAwithRSA", getProviderName());
    }

    @Test
    public void testSignature_SHA_1_RSA() throws Exception {
        Signature.getInstance("SHA-1/RSA", getProviderName());
    }

    @Test
    public void testSignature_SHA1_RSA() throws Exception {
        Signature.getInstance("SHA1/RSA", getProviderName());
    }

    @Test
    public void testSignature_SHA_RSA() throws Exception {
        Signature.getInstance("SHA/RSA", getProviderName());
    }

    @Test
    public void testSignature_RSA() throws Exception {
        Signature.getInstance("RSA", getProviderName());
    }

    @Test
    public void testSignature_SHA224_RSA() throws Exception {
        Signature.getInstance("SHA224/RSA", getProviderName());
    }

    @Test
    public void testSignature_SHA2withRSA() throws Exception {
        Signature.getInstance("SHA2withRSA", getProviderName());
    }

    @Test
    public void testSignature_SHA2_RSA() throws Exception {
        Signature.getInstance("SHA2/RSA", getProviderName());
    }

    @Test
    public void testSignature_SHA3withRSA() throws Exception {
        Signature.getInstance("SHA3withRSA", getProviderName());
    }

    @Test
    public void testSignature_SHA3_RSA() throws Exception {
        Signature.getInstance("SHA3/RSA", getProviderName());
    }

    @Test
    public void testSignature_SHA5withRSA() throws Exception {

        Signature.getInstance("SHA5withRSA", getProviderName());
    }

    @Test
    public void testSignature_SHA5_RSA() throws Exception {
        Signature.getInstance("SHA5/RSA", getProviderName());
    }

    @Test
    public void testAliases() throws Exception {
        System.out.println("executing testAliases SHA5/RSA");
        Signature.getInstance("SHA5/RSA", getProviderName());
    }
}

