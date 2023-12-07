/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class BaseTestECDSASignature extends BaseTestSignature {

    // --------------------------------------------------------------------------
    //
    //
    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    // --------------------------------------------------------------------------
    //
    //
    public BaseTestECDSASignature(String providerName) {
        super(providerName);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {}

    // --------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA1withECDSA_192() throws Exception {
        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports cuirve P-192. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(192);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA1withECDSA_224() throws Exception {
        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports SHA-1. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(224);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA1withECDSA_256() throws Exception {
        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports SHA-1. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(256);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA1withECDSA_384() throws Exception {
        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports SHA-1. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(384);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA1withECDSA_521() throws Exception {
        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports SHA-1. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(521);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA224withECDSA_192() throws Exception {
        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports cuirve P-192. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(192);
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA224withECDSA_224() throws Exception {
        KeyPair keyPair = generateKeyPair(224);
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA224withECDSA_256() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA224withECDSA_384() throws Exception {
        KeyPair keyPair = generateKeyPair(384);
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA224withECDSA_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA256withECDSA_192() throws Exception {
        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports cuirve P-192. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(192);
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA256withECDSA_224() throws Exception {
        KeyPair keyPair = generateKeyPair(224);
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA256withECDSA_256() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA256withECDSA_384() throws Exception {
        KeyPair keyPair = generateKeyPair(384);
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA256withECDSA_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA384withECDSA_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        doSignVerify("SHA384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA512withECDSA_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        doSignVerify("SHA512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testSHA3_224withECDSA_192() throws Exception {
        try {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                //FIPS no longer supports cuirve P-192. So skip test
                return;
            }
            KeyPair keyPair = generateKeyPair(192);
            doSignVerify("SHA3-224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_256withECDSA_192() throws Exception {
        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports cuirve P-192. So skip test
            return;
        }
        try {
            KeyPair keyPair = generateKeyPair(192);
            doSignVerify("SHA3-256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_384withECDSA_192() throws Exception {
        try {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                //FIPS no longer supports cuirve P-192. So skip test
                return;
            }
            KeyPair keyPair = generateKeyPair(192);
            doSignVerify("SHA3-384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_512withECDSA_192() throws Exception {
        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports cuirve P-192. So skip test
            return;
        }
        try {
            KeyPair keyPair = generateKeyPair(192);
            doSignVerify("SHA3-512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_224withECDSA_224() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(224);
            doSignVerify("SHA3-224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_256withECDSA_224() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(224);
            doSignVerify("SHA3-256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_384withECDSA_224() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(224);
            doSignVerify("SHA3-384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_512withECDSA_224() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(224);
            doSignVerify("SHA3-512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_224withECDSA_256() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(256);
            doSignVerify("SHA3-224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_256withECDSA_256() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(256);
            doSignVerify("SHA3-256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_384withECDSA_256() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(256);
            doSignVerify("SHA3-384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_512withECDSA_256() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(256);
            doSignVerify("SHA3-512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_224withECDSA_384() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(384);
            doSignVerify("SHA3-224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_256withECDSA_384() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(384);
            doSignVerify("SHA3-256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_384withECDSA_384() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(384);
            doSignVerify("SHA3-384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_512withECDSA_384() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(384);
            doSignVerify("SHA3-512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_224withECDSA_521() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(521);
            doSignVerify("SHA3-224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_256withECDSA_521() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(521);
            doSignVerify("SHA3-256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_384withECDSA_521() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(521);
            doSignVerify("SHA3-384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testSHA3_512withECDSA_521() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(521);
            doSignVerify("SHA3-512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
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
    public void testDatawithECDSA_192() throws Exception {
        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports cuirve P-192. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(192);
        MessageDigest md = MessageDigest.getInstance("SHA-1", providerName);
        md.update(origMsg);
        byte[] digest = md.digest();
        doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testDatawithECDSA_224() throws Exception {
        KeyPair keyPair = generateKeyPair(224);
        MessageDigest md = MessageDigest.getInstance("SHA-224", providerName);
        md.update(origMsg);
        byte[] digest = md.digest();
        doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testDatawithECDSA_256() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        MessageDigest md = MessageDigest.getInstance("SHA-256", providerName);
        md.update(origMsg);
        byte[] digest = md.digest();
        doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testDatawithECDSA_384() throws Exception {
        KeyPair keyPair = generateKeyPair(384);
        MessageDigest md = MessageDigest.getInstance("SHA-384", providerName);
        md.update(origMsg);
        byte[] digest = md.digest();
        doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testDatawithECDSA_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        MessageDigest md = MessageDigest.getInstance("SHA-512", providerName);
        md.update(origMsg);
        byte[] digest = md.digest();
        doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testDatawithECDSA_longdgst_err_224() throws Exception {
        KeyPair keyPair = generateKeyPair(224);
        MessageDigest md = MessageDigest.getInstance("SHA-256", providerName);
        md.update(origMsg);
        byte[] digest = md.digest();
        try {
            doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
            assertTrue(false);
        } catch (SignatureException ex) {
            assertTrue(true);
        } catch (Exception ex) {
            assertTrue(true);
        }
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testDatawithECDSA_longdgst_err_256() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        MessageDigest md = MessageDigest.getInstance("SHA-512", providerName);
        md.update(origMsg);
        byte[] digest = md.digest();
        try {
            doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
            assertTrue(false);
        } catch (SignatureException ex) {
            assertTrue(true);
        } catch (Exception ex) {
            assertTrue(true);
        }
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testDatawithECDSA_longdgst_err_384() throws Exception {
        KeyPair keyPair = generateKeyPair(384);
        MessageDigest md = MessageDigest.getInstance("SHA-512", providerName);
        md.update(origMsg);
        byte[] digest = md.digest();
        try {
            doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
            assertTrue(false);
        } catch (SignatureException ex) {
            assertTrue(true);
        } catch (Exception ex) {
            assertTrue(true);
        }
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testDatawithECDSA_longdgst_err_512() throws Exception {
        KeyPair keyPair = generateKeyPair(512);
        MessageDigest md = MessageDigest.getInstance("SHA-512", providerName);
        md.update(origMsg);
        byte[] digest = md.digest();
        byte[] digestLarge = new byte[digest.length * 2];
        digestLarge = Arrays.copyOf(digest, digest.length);

        try {
            doSignVerify("NONEwithECDSA", digestLarge, keyPair.getPrivate(), keyPair.getPublic());
            assertTrue(false);
        } catch (SignatureException ex) {
            assertTrue(true);
        } catch (Exception ex) {
            assertTrue(true);
        }
    }

    public void testDatawithECDSA_longdgst_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        MessageDigest md = MessageDigest.getInstance("SHA-512", providerName);
        md.update(origMsg);
        byte[] digest = md.digest();
        byte[] digestLarge = new byte[digest.length * 2];
        digestLarge = Arrays.copyOf(digest, digest.length);

        try {
            doSignVerify("NONEwithECDSA", digestLarge, keyPair.getPrivate(), keyPair.getPublic());
            assertTrue(true);
        } catch (SignatureException ex) {
            assertTrue(false);
        }
    }

    /* Tests with supported curveNames */
    public void testSHA256withECDSA_256curves() throws Exception {

        KeyPair keyPair = null;
        if (!providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS does not support these curves. So skip test
            keyPair = generateKeyPair("secp256k1");
            doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

            keyPair = generateKeyPair("1.3.132.0.10");
            doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        }


        keyPair = generateKeyPair("secp256r1");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("NIST P-256");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("X9.62 prime256v1");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("1.2.840.10045.3.1.7");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

    }

    public void testSHA256withECDSA_384curves() throws Exception {
        KeyPair keyPair = generateKeyPair("secp384r1");
        doSignVerify("SHA384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("1.3.132.0.34");
        doSignVerify("SHA384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("NIST P-384");
        doSignVerify("SHA384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

    }

    public void testSHA256withECDSA_521curves() throws Exception {
        KeyPair keyPair = generateKeyPair("secp521r1");
        doSignVerify("SHA512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("1.3.132.0.35");
        doSignVerify("SHA512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("NIST P-521");
        doSignVerify("SHA512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

    }

    public void testSHA224withECDSA_160curves() throws Exception {
        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports cuirve P-192. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair("secp160k1");
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("1.3.132.0.9");
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("secp160r1");
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        keyPair = generateKeyPair("1.3.132.0.8");
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("secp160r2");
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        keyPair = generateKeyPair("1.3.132.0.30");
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());


    }

    public void testSHA224withECDSA_192curves() throws Exception {

        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports cuirve P-192. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair("secp192k1");
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        keyPair = generateKeyPair("1.3.132.0.31");
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("secp192r1");
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        keyPair = generateKeyPair("NIST P-192");
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("X9.62 prime192v1");
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        keyPair = generateKeyPair("1.2.840.10045.3.1.1");
        doSignVerify("SHA224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    public void testSHA224withECDSA_124curves() throws Exception {

        KeyPair keyPair = null;
        if (!providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS does not support this. so skip test
            keyPair = generateKeyPair("secp224k1");
            doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
            keyPair = generateKeyPair("1.3.132.0.32");
            doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        }

        keyPair = generateKeyPair("secp224r1");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        keyPair = generateKeyPair("NIST P-224");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        keyPair = generateKeyPair("1.3.132.0.33");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

    }

    public void testX962PrimeCurves() throws Exception {


        /* ANSI X9.62 prime curves */

        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS does not support this. so skip test
            return;
        }
        KeyPair keyPair = generateKeyPair("X9.62 prime192v2");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("1.2.840.10045.3.1.2");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("X9.62 prime192v3");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        keyPair = generateKeyPair("1.2.840.10045.3.1.3");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("X9.62 prime239v1");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        keyPair = generateKeyPair("1.2.840.10045.3.1.4");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("X9.62 prime239v2");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        keyPair = generateKeyPair("1.2.840.10045.3.1.5");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("X9.62 prime239v3");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("1.2.840.10045.3.1.6");
        doSignVerify("SHA256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    // OSB Oracle Security Fix 8277233 test
    public void testPostiveSigBytes() throws Exception {
        doTestPositiveSigBytes("EC", "SHA256withECDSA", this.providerName);

        if (!providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS does not support this. so skip test
            doTestPositiveSigBytes("DSA", "SHA256withDSA", this.providerName);
        }
    }

    void doTestPositiveSigBytes(String keyAlg, String sigAlg, String providerName)
            throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlg, providerName);
        KeyPair kp = kpg.generateKeyPair();

        Signature signer = Signature.getInstance(sigAlg, providerName);
        signer.initSign(kp.getPrivate());

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

    // --------------------------------------------------------------------------
    //
    //
    private KeyPair generateKeyPair(int keysize) throws Exception {
        KeyPairGenerator ecKeyPairGen = KeyPairGenerator.getInstance("EC", providerName);
        ecKeyPairGen.initialize(keysize);
        return ecKeyPairGen.generateKeyPair();
    }

    private KeyPair generateKeyPair(String curveName) throws Exception {
        KeyPairGenerator ecKeyPairGen = KeyPairGenerator.getInstance("EC", providerName);
        ECGenParameterSpec ecgenParameterSpec = new ECGenParameterSpec(curveName);
        ecKeyPairGen.initialize(ecgenParameterSpec);
        return ecKeyPairGen.generateKeyPair();
    }

}
