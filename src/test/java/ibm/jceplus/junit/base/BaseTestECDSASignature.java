/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestECDSASignature extends BaseTestJunit5Signature {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    @Test
    public void testEngineSetParameter_invalidSpec() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        
        String sigAlgo = "SHA256withECDSA";
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        AlgorithmParameters pssParams = AlgorithmParameters.getInstance("RSASSA-PSS", getProviderName());
        pssParams.init(new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, 1));
        PSSParameterSpec pssParameterSpec = pssParams.getParameterSpec(PSSParameterSpec.class);

        AlgorithmParameters ecParams = AlgorithmParameters.getInstance("EC", getProviderName());
        ecParams.init(new ECGenParameterSpec("secp521r1"));
        ECParameterSpec ecParameterSpec = ecParams.getParameterSpec(ECParameterSpec.class);

        Signature signing = Signature.getInstance(sigAlgo, getProviderName());
        signing.initSign(privateKey);

        // Check with different type of AlgorithmParameterSpec.
        try {
            signing.setParameter(pssParameterSpec);
        } catch (InvalidAlgorithmParameterException iape) {
            if (!"Parameters must be of type ECParameterSpec".equals(iape.getMessage())) {
                throw iape;
            }
        }

        // Check against private key with same type of AlgorithmParameterSpec, but different curve.
        try {
            signing.setParameter(ecParameterSpec);
            fail("InvalidAlgorithmParameterException expected.");
        } catch (InvalidAlgorithmParameterException iape) {
            if (!"Signature params does not match key params".equals(iape.getMessage())) {
                throw iape;
            }
        }

        Signature verifying = Signature.getInstance(sigAlgo, getProviderName());
        verifying.initVerify(publicKey);

        // Check against public key with same type of AlgorithmParameterSpec, but different curve.
        try {
            verifying.setParameter(ecParameterSpec);
            fail("InvalidAlgorithmParameterException expected.");
        } catch (InvalidAlgorithmParameterException iape) {
            if (!"Signature params does not match key params".equals(iape.getMessage())) {
                throw iape;
            }
        }
    }

    @Test
    public void testEngineSetParameter_validSpec() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        
        String sigAlgo = "SHA256withECDSA";
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", getProviderName());
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecParameters = params.getParameterSpec(ECParameterSpec.class);

        Signature signing = Signature.getInstance(sigAlgo, getProviderName());
        signing.initSign(privateKey);
        // Check against private key with correct AlgorithmParameterSpec.
        signing.setParameter(ecParameters);

        Signature verifying = Signature.getInstance(sigAlgo, getProviderName());
        verifying.initVerify(publicKey);
        // Check against public key with correct AlgorithmParameterSpec.
        verifying.setParameter(ecParameters);
    }

    @Test
    public void testSHA1withECDSA_192() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports cuirve P-192. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(192);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA1withECDSA_224() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports SHA-1. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(224);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA1withECDSA_256() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports SHA-1. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(256);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA1withECDSA_384() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports SHA-1. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(384);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA1withECDSA_521() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports SHA-1. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(521);
        doSignVerify("SHA1withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA224withECDSA_192() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports cuirve P-192. So skip test
            return;
        }
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
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports cuirve P-192. So skip test
            return;
        }
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
    public void testSHA384withECDSA_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        doSignVerify("SHA384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA512withECDSA_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        doSignVerify("SHA512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_224withECDSA_192() throws Exception {
        try {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                //FIPS no longer supports cuirve P-192. So skip test
                return;
            }
            KeyPair keyPair = generateKeyPair(192);
            doSignVerify("SHA3-224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_256withECDSA_192() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports cuirve P-192. So skip test
            return;
        }
        try {
            KeyPair keyPair = generateKeyPair(192);
            doSignVerify("SHA3-256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_384withECDSA_192() throws Exception {
        try {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                //FIPS no longer supports cuirve P-192. So skip test
                return;
            }
            KeyPair keyPair = generateKeyPair(192);
            doSignVerify("SHA3-384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_512withECDSA_192() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports cuirve P-192. So skip test
            return;
        }
        try {
            KeyPair keyPair = generateKeyPair(192);
            doSignVerify("SHA3-512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_224withECDSA_224() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(224);
            doSignVerify("SHA3-224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_256withECDSA_224() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(224);
            doSignVerify("SHA3-256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_384withECDSA_224() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(224);
            doSignVerify("SHA3-384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_512withECDSA_224() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(224);
            doSignVerify("SHA3-512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_224withECDSA_256() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(256);
            doSignVerify("SHA3-224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_256withECDSA_256() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(256);
            doSignVerify("SHA3-256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_384withECDSA_256() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(256);
            doSignVerify("SHA3-384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_512withECDSA_256() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(256);
            doSignVerify("SHA3-512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_224withECDSA_384() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(384);
            doSignVerify("SHA3-224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_256withECDSA_384() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(384);
            doSignVerify("SHA3-256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_384withECDSA_384() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(384);
            doSignVerify("SHA3-384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_512withECDSA_384() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(384);
            doSignVerify("SHA3-512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_224withECDSA_521() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(521);
            doSignVerify("SHA3-224withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_256withECDSA_521() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(521);
            doSignVerify("SHA3-256withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_384withECDSA_521() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(521);
            doSignVerify("SHA3-384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_512withECDSA_521() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(521);
            doSignVerify("SHA3-512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testDatawithECDSA_192() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports cuirve P-192. So skip test
            return;
        }
        KeyPair keyPair = generateKeyPair(192);
        MessageDigest md = MessageDigest.getInstance("SHA-1", getProviderName());
        md.update(origMsg);
        byte[] digest = md.digest();
        doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testDatawithECDSA_224() throws Exception {
        KeyPair keyPair = generateKeyPair(224);
        MessageDigest md = MessageDigest.getInstance("SHA-224", getProviderName());
        md.update(origMsg);
        byte[] digest = md.digest();
        doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testDatawithECDSA_256() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        MessageDigest md = MessageDigest.getInstance("SHA-256", getProviderName());
        md.update(origMsg);
        byte[] digest = md.digest();
        doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testDatawithECDSA_384() throws Exception {
        KeyPair keyPair = generateKeyPair(384);
        MessageDigest md = MessageDigest.getInstance("SHA-384", getProviderName());
        md.update(origMsg);
        byte[] digest = md.digest();
        doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testDatawithECDSA_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        MessageDigest md = MessageDigest.getInstance("SHA-512", getProviderName());
        md.update(origMsg);
        byte[] digest = md.digest();
        doSignVerify("NONEwithECDSA", digest, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testDatawithECDSA_longdgst_err_224() throws Exception {
        KeyPair keyPair = generateKeyPair(224);
        MessageDigest md = MessageDigest.getInstance("SHA-256", getProviderName());
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

    @Test
    public void testDatawithECDSA_longdgst_err_256() throws Exception {
        KeyPair keyPair = generateKeyPair(256);
        MessageDigest md = MessageDigest.getInstance("SHA-512", getProviderName());
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

    @Test
    public void testDatawithECDSA_longdgst_err_384() throws Exception {
        KeyPair keyPair = generateKeyPair(384);
        MessageDigest md = MessageDigest.getInstance("SHA-512", getProviderName());
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

    @Test
    public void testDatawithECDSA_longdgst_521() throws Exception {
        KeyPair keyPair = generateKeyPair(521);
        MessageDigest md = MessageDigest.getInstance("SHA-512", getProviderName());
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

    /**
     *  Tests with supported curveNames
     */
    @Test
    public void testSHA256withECDSA_256curves() throws Exception {

        KeyPair keyPair = null;
        if (!getProviderName().equals("OpenJCEPlusFIPS")) {
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

    @Test
    public void testSHA256withECDSA_384curves() throws Exception {
        KeyPair keyPair = generateKeyPair("secp384r1");
        doSignVerify("SHA384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("1.3.132.0.34");
        doSignVerify("SHA384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("NIST P-384");
        doSignVerify("SHA384withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

    }

    @Test
    public void testSHA256withECDSA_521curves() throws Exception {
        KeyPair keyPair = generateKeyPair("secp521r1");
        doSignVerify("SHA512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("1.3.132.0.35");
        doSignVerify("SHA512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

        keyPair = generateKeyPair("NIST P-521");
        doSignVerify("SHA512withECDSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());

    }

    @Test
    public void testSHA224withECDSA_160curves() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
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

    @Test
    public void testSHA224withECDSA_192curves() throws Exception {

        if (getProviderName().equals("OpenJCEPlusFIPS")) {
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

    @Test
    public void testSHA224withECDSA_124curves() throws Exception {

        KeyPair keyPair = null;
        if (!getProviderName().equals("OpenJCEPlusFIPS")) {
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

    @Test
    public void testX962PrimeCurves() throws Exception {


        /* ANSI X9.62 prime curves */

        if (getProviderName().equals("OpenJCEPlusFIPS")) {
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

    @Test
    public void testPostiveSigBytes() throws Exception {
        doTestPositiveSigBytes("EC", "SHA256withECDSA", this.getProviderName());

        if (!getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support this. so skip test
            doTestPositiveSigBytes("DSA", "SHA256withDSA", this.getProviderName());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"secp256r1", "secp384r1", "secp521r1"})
    public void testECDSASignatureWithInvalidKeySpec(String curveName) throws Exception {
        ECPrivateKey ecPrivKey = generateInvalidPrivateKey(curveName);
        Signature sig = Signature.getInstance("SHA256withECDSA", this.getProviderName());
        try {
            sig.initSign(ecPrivKey);
            fail("Expected <java.security.InvalidKeyException> to be thrown");
        } catch (java.security.InvalidKeyException ike) {
            System.out.println("Expected exception <java.security.InvalidKeyException> for " +
                                "ECDSA/SHA256withECDSA/" + curveName + "is caught.");
        }
    }

    private void doTestPositiveSigBytes(String keyAlg, String sigAlg, String providerName)
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


    private KeyPair generateKeyPair(int keysize) throws Exception {
        KeyPairGenerator ecKeyPairGen = KeyPairGenerator.getInstance("EC", getProviderName());
        ecKeyPairGen.initialize(keysize);
        return ecKeyPairGen.generateKeyPair();
    }

    private KeyPair generateKeyPair(String curveName) throws Exception {
        KeyPairGenerator ecKeyPairGen = KeyPairGenerator.getInstance("EC", getProviderName());
        ECGenParameterSpec ecgenParameterSpec = new ECGenParameterSpec(curveName);
        ecKeyPairGen.initialize(ecgenParameterSpec);
        return ecKeyPairGen.generateKeyPair();
    }

    public final ECPrivateKey generateInvalidPrivateKey(String curveName) throws Exception {
        System.out.println("Creating private key for curve " + curveName);

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", getProviderName());
        params.init(new ECGenParameterSpec(curveName));
        ECParameterSpec ecParameters = params.getParameterSpec(ECParameterSpec.class);
        BigInteger order = ecParameters.getOrder(); // the N value
        System.out.println("Order is: " + order);

        // Create a private key value (d) that is outside the range
        // [1, N-1]
        BigInteger dVal = order.add(BigInteger.TWO);
        System.out.println("Modified d Value is: " + dVal);

        // Create the private key
        KeyFactory kf = KeyFactory.getInstance("EC", getProviderName());
        return (ECPrivateKey) kf.generatePrivate(new ECPrivateKeySpec(dVal, ecParameters));
    }
}
