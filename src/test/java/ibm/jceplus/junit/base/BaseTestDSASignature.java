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
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class BaseTestDSASignature extends BaseTestJunit5Signature {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    @Test
    public void testSHA1withDSA_1024() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(1024);
            doSignVerify("SHA1withDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }

    }

    @Test
    public void testSHA224withDSA_1024() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(1024);
            doSignVerify("SHA224withDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA256withDSA_1024() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(1024);
            doSignVerify("SHA256withDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_224withDSA_1024() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(1024);
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
    public void testSHA3_2564withDSA_1024() throws Exception {
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
    public void testDSAforSSL_1024_hash1() throws Exception {
        KeyPair keyPair = null;
        try {
            keyPair = generateKeyPair(1024);
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
                return;
            } else {
                assertTrue(false);
            }
        }
        byte[] sslHash = Arrays.copyOf(origMsg, 1);
        try {
            doSignVerify("DSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
            fail("Did not get expected SignatureException");
        } catch (SignatureException se) {
            assertTrue(true);
        } catch (Exception e) {
            fail("Expected SignatureException, got " + e.toString());
        }
    }

    @Test
    public void testDSAforSSL_1024_hash19() throws Exception {
        KeyPair keyPair = null;
        try {
            keyPair = generateKeyPair(1024);
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
                return;
            } else {
                assertTrue(false);
            }
        }
        byte[] sslHash = Arrays.copyOf(origMsg, 19);
        try {
            doSignVerify("DSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
            fail("Did not get expected SignatureException");
        } catch (SignatureException se) {
        } catch (Exception e) {
            fail("Expected SignatureException, got " + e.toString());
        }

    }

    @Test
    public void testDSAforSSL_1024_hash20() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(1024);
            byte[] sslHash = Arrays.copyOf(origMsg, 20);
            doSignVerify("DSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }

    }

    @Test
    public void testDSAforSSL_1024_hash21() throws Exception {
        KeyPair keyPair = null;
        try {

            keyPair = generateKeyPair(1024);
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
                return;
            } else {
                assertTrue(false);
            }
        }
        byte[] sslHash = Arrays.copyOf(origMsg, 21);
        try {
            doSignVerify("DSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
            fail("Did not get expected SignatureException");
        } catch (SignatureException se) {
        } catch (Exception e) {
            fail("Expected SignatureException, got " + e.toString());
        }

    }

    @Test
    public void testNONEwithDSA_1024_hash20() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(1024);
            byte[] sslHash = Arrays.copyOf(origMsg, 20);
            doSignVerify("NONEwithDSA", sslHash, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }

    }

    @Test
    public void testDSASignatureUpdates() throws Exception {
        for (int updBufferSize = 64; updBufferSize <= 512;) {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA", getProviderName());
            keyPairGen.initialize(2048);
            KeyPair pair = keyPairGen.generateKeyPair();
            PrivateKey privKey = pair.getPrivate();
            Signature signature = Signature.getInstance("SHA256withDSA", getProviderName());
            signature.initSign(privKey);
            doDSASignatureUpdates(signature, updBufferSize);
            signature.sign();
            updBufferSize += 32;
        }
    }

    protected void doDSASignatureUpdates(Signature sign, int updBufferSize) throws SignatureException {
        if (updBufferSize < 128) {
            sign.update((byte) updBufferSize);
        } else {
            byte[] data = new byte[5];
            int off = data.length;
            while (true) {
                data[--off] = (byte) updBufferSize;
                updBufferSize >>>= 8;
                if (updBufferSize == 0) {
                    int len = data.length - off;
                    data[--off] = (byte) (0x80 | len++);
                    sign.update(data, off, len);
                    break;
                }
            }
        }
    }

    protected KeyPair generateKeyPair(int keysize) throws Exception {
        KeyPairGenerator dsaKeyPairGen = KeyPairGenerator.getInstance("DSA", getProviderName());
        dsaKeyPairGen.initialize(keysize);
        return dsaKeyPairGen.generateKeyPair();
    }

    protected KeyPair generateKeyPairFromEncoded(int keysize) throws Exception {
        KeyPairGenerator dsaKeyPairGen = KeyPairGenerator.getInstance("DSA", getProviderName());
        dsaKeyPairGen.initialize(keysize);
        KeyPair keyPair = dsaKeyPairGen.generateKeyPair();

        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());

        KeyFactory dsaKeyFactory = KeyFactory.getInstance("DSA", getProviderName());

        PublicKey publicKey = dsaKeyFactory.generatePublic(x509Spec);
        PrivateKey privateKey = dsaKeyFactory.generatePrivate(pkcs8Spec);
        return new KeyPair(publicKey, privateKey);
    }

    protected KeyPair generateKeyPairFromSpec() throws Exception {
        return null;
    }
}
