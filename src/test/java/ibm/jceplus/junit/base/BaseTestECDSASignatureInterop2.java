/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import org.junit.jupiter.api.Test;

public class BaseTestECDSASignatureInterop2 extends BaseTestSignatureInterop {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    @Test
    public void testSHA1withDSA_192() throws Exception {
        KeyPair keyPair = generateKeyPair(192);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA1withDSA_224() throws Exception {
        KeyPair keyPair = generateKeyPair(224);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA1withDSA_256() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA1withECDSA_384() throws Exception {
        KeyPair keyPair = generateKeyPair(384);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA1withECDSA_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA224withECDSA_192() throws Exception {
        KeyPair keyPair = generateKeyPair(192);
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA224withECDSA_224() throws Exception {
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

    @Test
    public void testSHA256withECDSA_192() throws Exception {
        KeyPair keyPair = generateKeyPair(192);
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA256withECDSA_224() throws Exception {
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

    @Test
    public void testSHA3_224withECDSA_192() throws Exception {
        KeyPair keyPair = generateKeyPair(192);
        doSignVerify("SHA3-224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_256withECDSA_192() throws Exception {
        KeyPair keyPair = generateKeyPair(192);
        doSignVerify("SHA3-256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_384withECDSA_192() throws Exception {
        KeyPair keyPair = generateKeyPair(192);
        doSignVerify("SHA3-384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_512withECDSA_192() throws Exception {
        KeyPair keyPair = generateKeyPair(192);
        doSignVerify("SHA3-512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_224withECDSA_224() throws Exception {
        KeyPair keyPair = generateKeyPair(224);
        doSignVerify("SHA3-224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_256withECDSA_224() throws Exception {
        KeyPair keyPair = generateKeyPair(224);
        doSignVerify("SHA3-256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_384withECDSA_224() throws Exception {
        KeyPair keyPair = generateKeyPair(224);
        doSignVerify("SHA3-384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_512withECDSA_224() throws Exception {
        KeyPair keyPair = generateKeyPair(224);
        doSignVerify("SHA3-512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_224withECDSA_256() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        doSignVerify("SHA3-224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_256withECDSA_256() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        doSignVerify("SHA3-256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_384withECDSA_256() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        doSignVerify("SHA3-384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_512withECDSA_256() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        doSignVerify("SHA3-512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_224withECDSA_384() throws Exception {
        KeyPair keyPair = generateKeyPair(384);
        doSignVerify("SHA3-224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_256withECDSA_384() throws Exception {
        KeyPair keyPair = generateKeyPair(384);
        doSignVerify("SHA3-256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_384withECDSA_384() throws Exception {
        KeyPair keyPair = generateKeyPair(384);
        doSignVerify("SHA3-384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_512withECDSA_384() throws Exception {
        KeyPair keyPair = generateKeyPair(384);
        doSignVerify("SHA3-512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_224withECDSA_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        doSignVerify("SHA3-224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_256withECDSA_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        doSignVerify("SHA3-256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_384withECDSA_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        doSignVerify("SHA3-384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_512withECDSA_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        doSignVerify("SHA3-512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testDatawithECDSA_SHA1_192() throws Exception {
        KeyPair keyPair = generateKeyPair(192);
        MessageDigest md = MessageDigest.getInstance("SHA-1", getProviderName());
        md.update(origMsg);
        byte[] digest = md.digest();
        //System.out.println ("origMessage.length" + origMsg.length);
        doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testDatawithECDSA_SHA224_224() throws Exception {
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
