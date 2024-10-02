/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import org.junit.Ignore;
import org.junit.jupiter.api.Test;
import static org.junit.Assert.assertTrue;

public class BaseTestECDSASignatureInterop extends BaseTestSignatureInterop {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    @Ignore("Curve secp192r1 removed via https://bugs.openjdk.org/browse/JDK-8251547 in JDK16")
    public void ignore_testSHA1withDSA_192() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support SHA-1 or P-192. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(192);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }


    @Ignore("Curve secp224r1 removed via https://bugs.openjdk.org/browse/JDK-8251547 in JDK16")
    public void ignore_testSHA1withDSA_224() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support SHA-1. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(224);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA1withDSA_256() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support SHA-1. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(256);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA1withECDSA_384() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support SHA-1. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(384);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA1withECDSA_521() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support SHA-1. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(521);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }


    @Ignore("Curve secp192r1 removed via https://bugs.openjdk.org/browse/JDK-8251547 in JDK16")
    public void ignore_testSHA224withECDSA_192() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support P-192. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(192);
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }


    @Ignore("Curve secp224r1 removed via https://bugs.openjdk.org/browse/JDK-8251547 in JDK16")
    public void ignore_testSHA224withECDSA_224() throws Exception {

        KeyPair keyPair = generateKeyPair(224);
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA224withECDSA_256() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA224withECDSA_384() throws Exception {
        KeyPair keyPair = generateKeyPair(384);
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA224withECDSA_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }


    @Ignore("Curve secp192r1 removed via https://bugs.openjdk.org/browse/JDK-8251547 in JDK16")
    public void ignore_testSHA256withECDSA_192() throws Exception {

        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support P-192. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(192);
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }


    @Ignore("Curve secp224r1 removed via https://bugs.openjdk.org/browse/JDK-8251547 in JDK16")
    public void ignore_testSHA256withECDSA_224() throws Exception {

        KeyPair keyPair = generateKeyPair(224);
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA256withECDSA_256() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA256withECDSA_384() throws Exception {
        KeyPair keyPair = generateKeyPair(384);
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA256withECDSA_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }


    @Ignore("Curve secp192r1 removed via https://bugs.openjdk.org/browse/JDK-8251547 in JDK16")
    public void ignore_testDatawithECDSA_SHA1_192() throws Exception {

        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support P-192 and SHA-1. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(192);
        MessageDigest md = MessageDigest.getInstance("SHA-1", getProviderName());
        md.update(origMsg);
        byte[] digest = md.digest();
        //System.out.println ("origMessage.length" + origMsg.length);
        doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
    }


    @Ignore("Curve secp224r1 removed via https://bugs.openjdk.org/browse/JDK-8251547 in JDK16")
    public void ignore_testDatawithECDSA_SHA224_224() throws Exception {
        KeyPair keyPair = generateKeyPair(224);
        MessageDigest md = MessageDigest.getInstance("SHA-224", getProviderName());
        md.update(origMsg);
        byte[] digest = md.digest();
        //System.out.println ("origMessage.length" + origMsg.length);
        doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testDatawithECDSA_SHA256_256() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        MessageDigest md = MessageDigest.getInstance("SHA-256", getProviderName());
        md.update(origMsg);
        byte[] digest = md.digest();
        //System.out.println ("origMessage.length" + origMsg.length);
        doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testDatawithECDSA_SHA384_384() throws Exception {
        KeyPair keyPair = generateKeyPair(384);
        MessageDigest md = MessageDigest.getInstance("SHA-384", getProviderName());
        md.update(origMsg);
        byte[] digest = md.digest();
        //System.out.println ("origMessage.length" + origMsg.length);
        doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testDatawithECDSA_SHA512_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        MessageDigest md = MessageDigest.getInstance("SHA-512", getProviderName());
        md.update(origMsg);
        byte[] digest = md.digest();
        //System.out.println ("origMessage.length" + origMsg.length);
        doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
    }

    //OSB Oracle Security Fix 8277233 test
    @Test
    public void testPostiveSigBytes() throws Exception {
        doTestPositiveSigBytes("EC", "SHA256withECDSA", this.getProviderName());
        doTestPositiveSigBytes("EC", "SHA256withECDSA", this.getProviderName());

        if (!getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support DSA. So skip test
            doTestPositiveSigBytes("DSA", "SHA256withDSA", this.getProviderName());
            doTestPositiveSigBytes("DSA", "SHA256withDSA", this.getProviderName());
        }
    }


    void doTestPositiveSigBytes(String keyAlg, String sigAlg, String providerName)
            throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlg, providerName);
        KeyPair kp = kpg.generateKeyPair();

        Signature signer = Signature.getInstance(sigAlg, providerName);
        signer.initSign(kp.getPrivate());
        signer.sign();

        byte[] fakesig = new byte[] {0x30, 6, 2, 1, 0, 2, 1, 0};

        Signature verifier = Signature.getInstance(sigAlg, providerName);
        verifier.initVerify(kp.getPublic());
        verifier.update("whatever".getBytes(StandardCharsets.UTF_8));
        boolean result;
        try {
            result = verifier.verify(fakesig);
            if (result) {
                assertTrue(false);
            } else {
                assertTrue(true);
            }
        } catch (Exception e) {
            return;
        }
    }

    @Test
    public void testDatawithECDSA_NoHash_256() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        //MessageDigest md = MessageDigest.getInstance("SHA-256", providerName);
        //md.update(origMsg);
        //byte[] digest = md.digest();
        byte[] origMsg1 = "a".getBytes();
        //System.out.println ("origMessage.length" + origMsg.length);
        doSignVerify("NONEwithECDSA", origMsg1, keyPair.getPrivate(), keyPair.getPublic());
    }


    private KeyPair generateKeyPair(int keysize) throws Exception {
        KeyPairGenerator ecKeyPairGen = KeyPairGenerator.getInstance("EC", getProviderName());
        ecKeyPairGen.initialize(keysize);
        return ecKeyPairGen.generateKeyPair();
    }
}
