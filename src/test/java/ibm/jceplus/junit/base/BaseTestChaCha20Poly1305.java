/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import com.ibm.crypto.plus.provider.ChaCha20Constants;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestChaCha20Poly1305 extends BaseTestCipher implements ChaCha20Constants {


    // 14 bytes: PASSED
    static final byte[] PLAIN_TEXT_14 = "12345678123456".getBytes();

    // 16 bytes: PASSED
    static final byte[] PLAIN_TEXT_16 = "1234567812345678".getBytes();

    // 18 bytes: PASSED
    static final byte[] PLAIN_TEXT_18 = "123456781234567812".getBytes();

    // 63 bytes: PASSED
    static final byte[] PLAIN_TEXT_63 = "123456781234567812345678123456781234567812345678123456781234567"
            .getBytes();

    // 128 bytes: PASSED
    static final byte[] PLAIN_TEXT_128 = "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            .getBytes();

    static final byte[] PLAIN_TEXT = PLAIN_TEXT_128; // default value

    static final byte[] NONCE_11_BYTE = "12345678123".getBytes();
    static final byte[] NONCE_12_BYTE = "123456781234".getBytes();
    static final byte[] NONCEA_12_BYTE = "012345678123".getBytes();
    static final byte[] NONCE_13_BYTE = "1234567812345".getBytes();

    static final byte[] BAD_TAG_16 = "BaadTaagBaadTaag".getBytes();

    static final byte[] CHACHA20_POLY1305_AAD = "12345".getBytes(); //"ChaCha20-Poly1305 AAD".getBytes();

    static final String CHACHA20_POLY1305_ALGORITHM = "ChaCha20-Poly1305";
    static final String CHACHA20_ALGORITHM = "ChaCha20";

    static final IvParameterSpec CHACHA20_POLY1305_PARAM_SPEC = new IvParameterSpec(NONCE_12_BYTE);


    protected KeyGenerator keyGen = null;
    protected SecretKey key = null;
    protected IvParameterSpec paramSpec = null;
    protected Cipher cp = null;
    protected boolean success = true;
    protected int specifiedKeySize = 0;

    @BeforeEach
    public void setUp() throws Exception {
        keyGen = KeyGenerator.getInstance(CHACHA20_ALGORITHM, getProviderName());
        if (specifiedKeySize > 0) {
            keyGen.init(specifiedKeySize);
        }
        key = keyGen.generateKey();
    }

    @Test
    public void testChaCha20Poly1305IllegalKeyNonceReuse() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
            cp.init(Cipher.DECRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);

            //fail("Expected InvalidKeyException did not occur");

        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw e;
        }
    }

    @Test
    public void testChaCha20Poly1305ShortBuffer() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());

            // Encrypt the plain text
            cp.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = new byte[5];
            cp.doFinal(PLAIN_TEXT, 0, PLAIN_TEXT.length, cipherText);
            fail("Expected ShortBufferException did not occur");
        } catch (ShortBufferException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testChaCha20Poly1305EncryptAfterShortBufferRetry() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            IvParameterSpec ivParamSpec = new IvParameterSpec(NONCE_12_BYTE);

            // Encrypt the plain text
            cp.init(Cipher.ENCRYPT_MODE, key, ivParamSpec);
            byte[] cipherText = new byte[PLAIN_TEXT.length + 15];
            cp.doFinal(PLAIN_TEXT, 0, PLAIN_TEXT.length, cipherText);
            fail("Expected ShortBufferException did not occur");

        } catch (ShortBufferException ex) {
            System.out.println("Try retry with a larger buffer");
        }
        // try retry with a larger buffer
        try {
            byte[] largerCipherTextBuffer = new byte[PLAIN_TEXT.length + 16];
            cp.doFinal(PLAIN_TEXT, 0, PLAIN_TEXT.length, largerCipherTextBuffer);
            assertTrue(true);

        } catch (Exception ex) {
            ex.printStackTrace();
            fail("Retying with larger buffer should have worked with a larger buffer");
        }
    }

    @Test
    public void testChaCha20Poly1305DecryptAfterShortBufferRetry() throws Exception {
        byte[] cipherText = null;
        Cipher cpl = null;
        try {
            cpl = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            IvParameterSpec ivParamSpec = new IvParameterSpec(NONCEA_12_BYTE);

            // Encrypt the plain text
            cpl.init(Cipher.ENCRYPT_MODE, key, ivParamSpec);
            cipherText = cpl.doFinal(PLAIN_TEXT, 0, PLAIN_TEXT.length);

            ivParamSpec = cpl.getParameters().getParameterSpec(IvParameterSpec.class);

            cpl = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cpl.init(Cipher.DECRYPT_MODE, key, ivParamSpec);
            byte[] sbPlainText = new byte[15];
            System.out.println("cipherText.length=" + cipherText.length);
            System.out.println("sbPlainText.length=" + sbPlainText.length);
            cpl.doFinal(cipherText, 0, cipherText.length, sbPlainText, 0);
            fail("Failed to get ShortedBufferException");

        } catch (ShortBufferException ex) {
            System.out.println("Try retry with a larger buffer");
        }
        // try retry with a larger buffer
        try {
            byte[] lbPlainTextBuffer = new byte[PLAIN_TEXT.length];
            cpl.doFinal(cipherText, 0, cipherText.length, lbPlainTextBuffer, 0);
            assertTrue(Arrays.equals(PLAIN_TEXT, lbPlainTextBuffer));
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("Retying with larger buffer should have worked  with a larger buffer");
        }
    }

    @Test
    public void testChaCha20Poly1305GetBlockSizeEncryptDecrypt() throws Exception {
        chaCha20GetBlockSize(Cipher.ENCRYPT_MODE);
        chaCha20GetBlockSize(Cipher.DECRYPT_MODE);
    }


    public void chaCha20GetBlockSize(int opMode) throws Exception {
        IvParameterSpec chaCha20ParamSpec = new IvParameterSpec(NONCE_12_BYTE);
        cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
        cp.init(opMode, key, chaCha20ParamSpec);
        assertTrue((cp.getBlockSize() == ChaCha20_BLOCK_SIZE), "ChaCha20 Block size must be: " + ChaCha20_BLOCK_SIZE);
    }

    @Test
    public void testChaCha20Poly1305ValidTransformations() throws Exception {
        String transformation = null;
        try {
            transformation = CHACHA20_POLY1305_ALGORITHM;
            cp = Cipher.getInstance(transformation, getProviderName());
            transformation = "ChaCha20-Poly1305/None/NoPadding";
            cp = Cipher.getInstance(transformation, getProviderName());
        } catch (NoSuchAlgorithmException ex) {
            fail("NoSuchAlgorithmException occurred for transform: " + transformation);
        }
    }

    @Test
    public void testChaCha20Poly1305InvalidTransformation() throws Exception {
        String transformation = "BogusChaCha20-Poly1305/BogusMode/BogusPadding";
        try {
            cp = Cipher.getInstance(transformation, getProviderName());
            fail("Expected NoSuchAlgorithmException did not occur");
        } catch (NoSuchAlgorithmException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testChaCha20Poly1305NullKey() throws Exception {
        cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
        SecretKey nullKey = null;

        try {
            cp.init(Cipher.ENCRYPT_MODE, nullKey);
            fail("Expected InvalidKeyException did not occur");
        } catch (InvalidKeyException e) {
        }

        try {
            cp.init(Cipher.ENCRYPT_MODE, nullKey, SecureRandom.getInstance("SHA2DRBG"));
            fail("Expected InvalidKeyException did not occur");
        } catch (InvalidKeyException e) {
        }
    }

    @Test
    public void testChaCha20Poly1305NoParamSpec() throws Exception {

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = cp.doFinal(PLAIN_TEXT);

            paramSpec = cp.getParameters().getParameterSpec(IvParameterSpec.class);

            // Verify the text
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, paramSpec);
            byte[] newPlainText = cp.doFinal(cipherText, 0, cipherText.length);

            assertTrue(Arrays.equals(PLAIN_TEXT, newPlainText));

        } catch (Exception e) {
            fail("Got unexpected exception on encrypt/decrypt...");
        }
    }

    @Test
    public void testChaCha20Poly1305NullParamSpec() throws Exception {

        try {
            IvParameterSpec ivSpec = null;
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] cipherText = cp.doFinal(PLAIN_TEXT);

            paramSpec = cp.getParameters().getParameterSpec(IvParameterSpec.class);

            // Verify the text
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, paramSpec);
            byte[] newPlainText = cp.doFinal(cipherText, 0, cipherText.length);

            assertTrue(Arrays.equals(PLAIN_TEXT, newPlainText));

        } catch (Exception e) {
            fail("Got unexpected exception on encrypt/decrypt...");
        }
    }

    @Test
    public void testChaCha20Poly1305InvalidParamSpec() throws Exception {

        try {
            byte[] iv = null;
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            fail("Expected NullPointerException or InvalidAlgorithmParameterException");
        } catch (NullPointerException npe) {
        } catch (InvalidAlgorithmParameterException e) {
        }

        try {
            byte[] iv = null;
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, ivSpec);
            fail("Expected NullPointerException or InvalidAlgorithmParameterException");
        } catch (NullPointerException npe) {
        } catch (InvalidAlgorithmParameterException e) {
        }

        try {
            AlgorithmParameters algParameters = AlgorithmParameters
                    .getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, algParameters);
            fail("Expected NullPointerException or InvalidAlgorithmParameterException");
        } catch (NullPointerException npe) {
        } catch (InvalidAlgorithmParameterException e) {
        }

        try {
            AlgorithmParameters algParameters = AlgorithmParameters
                    .getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, algParameters);
            fail("Expected NullPointerException or InvalidAlgorithmParameterException");
        } catch (NullPointerException npe) {
        } catch (InvalidAlgorithmParameterException e) {
        }

        try {
            IvParameterSpec ivSpec = new IvParameterSpec(NONCE_11_BYTE);
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            fail("Expected NullPointerException or InvalidAlgorithmParameterException");
        } catch (NullPointerException npe) {
        } catch (InvalidAlgorithmParameterException e) {
        }

        try {
            IvParameterSpec ivSpec = new IvParameterSpec(NONCE_13_BYTE);
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, ivSpec);
            fail("Expected NullPointerException or InvalidAlgorithmParameterException");
        } catch (NullPointerException npe) {
        } catch (InvalidAlgorithmParameterException e) {
        }
    }

    @Test
    public void testChaCha20Poly1305EncryptUpdateAndDoFinalArguments() throws Exception {

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
            cp.update(PLAIN_TEXT);
            // Update AAD must be done before cipher update, or do final...
            cp.updateAAD(CHACHA20_POLY1305_AAD, 0, CHACHA20_POLY1305_AAD.length);
            fail("Did not get expected IllegalStateException(updateAAD)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
            cp.doFinal(PLAIN_TEXT);
            // Update AAD must be done before cipher update, or do final...
            cp.updateAAD(CHACHA20_POLY1305_AAD, 0, CHACHA20_POLY1305_AAD.length);
        } catch (Exception e) {
            e.printStackTrace();
            fail("got unexpected IllegalStateException(updateAAD)");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.updateAAD(CHACHA20_POLY1305_AAD, 0, CHACHA20_POLY1305_AAD.length);
            fail("Did not get expected IllegalStateException(Cipher not initialized)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.doFinal(new byte[0]);
            fail("Did not get expected IllegalStateException(Cipher not initialized)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null);
            fail("Did not get expected IllegalArgumentException on doFinal(null)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0]);
        } catch (Exception e) {
            fail("Did not expect exception on doFinal(new byte[0])");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0);
            fail("Did not get expected IllegalArgumentException on doFinal(null, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 1);
            fail("Did not get expected IllegalArgumentException on doFinal(null, 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0);
            fail("Did not get expected exception on doFinal(new byte[0], 0)");
        } catch (ShortBufferException e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 1);
            fail("Did not get expected IllegalArgumentException on doFinal(new byte[0], 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[cp.getOutputSize(0)], 1);
            fail("Did not get expected IllegalArgumentException on doFinal(new byte[cp.getOutputSize(0)], 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0, 0);
            fail("Did not get expected IllegalArgumentException on doFinal(null, 0, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 1, 0);
            fail("Did not get expected IllegalArgumentException on doFinal(null, 1, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0, 1);
            fail("Did not get expected IllegalArgumentException on doFinal(null, 0, 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0);
        } catch (Exception e) {
            fail("Got unexpected exception on doFinal(new byte[0], 0, 0)");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 1, 0);
            fail("Did not get expected IllegalArgumentException on doFinal(new byte[0], 1, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 1);
            fail("Did not get expected IllegalArgumentException on doFinal(new byte[0], 0, 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0, 0, null);
            fail("Did not get expected IllegalArgumentException on doFinal(new byte[0], 0, 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0, new byte[0]);
            fail("Did not get expected exception on doFinal(new byte[0], 0, 0, new byte[0])");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0, null, 0);
            fail("Did not get expected IllegalArgumentException on doFinal(new byte[0], 0, 0, null, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0, new byte[0], 0);
            fail("Did not get expected exception on doFinal(new byte[0], 0, 0, new byte[0], 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.update(new byte[0]);
            fail("Did not get expected IllegalStateException(Cipher not initialized)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null);
            fail("Did not get expected IllegalArgumentException on update(null)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0]);
        } catch (Exception e) {
            fail("Got unexpected exception on update(new byte[0])");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 0);
            fail("Did not get expected IllegalArgumentException on update(null, 0, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 1, 0);
            fail("Did not get expected IllegalArgumentException on update(null, 1, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 1);
            fail("Did not get expected IllegalArgumentException on update(null, 0, 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0);
        } catch (Exception e) {
            fail("Got unexpected exception on update(new byte[0], 0, 0)");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 1, 0);
            fail("Did not get expected IllegalArgumentException on update(new byte[0], 1, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 1);
            fail("Did not get expected IllegalArgumentException on update(new byte[0], 0, 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 0, null);
            fail("Did not get expected IllegalArgumentException on update(null, 0, 0, null)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 0, new byte[0]);
            fail("Did not get expected IllegalArgumentException on update(null, 0, 0, new byte[0])");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null);
        } catch (Exception e) {
            fail("Did not expect exception on update(new byte[0], 0, 0, null)");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, new byte[0]);
        } catch (Exception e) {
            fail("Did not expect exception on update(new byte[0], 0, 0, new byte[0])");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null, 0);
        } catch (Exception e) {
            fail("Did not expect exception on update(new byte[0], 0, 0, null, 0)");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null, 1);
        } catch (Exception e) {
            fail("Did not expect exception on update(new byte[0], 0, 0, null, 1)");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, new byte[0], 0);
        } catch (Exception e) {
            fail("Did not expect exception on update(new byte[0], 0, 0, new byte[0], 0)");
        }
    }

    @Test
    public void testChaCha20Poly1305DecryptUpdateAndDoFinalArguments() throws Exception {

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
            cp.updateAAD(CHACHA20_POLY1305_AAD, 0, CHACHA20_POLY1305_AAD.length);
            cp.doFinal(PLAIN_TEXT);

            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
            cp.update(PLAIN_TEXT);
            // Update AAD must be done before cipher update, or do final...
            cp.updateAAD(CHACHA20_POLY1305_AAD, 0, CHACHA20_POLY1305_AAD.length);
            fail("Did not get expected IllegalStateException(updateAAD)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
            cp.updateAAD(CHACHA20_POLY1305_AAD, 0, CHACHA20_POLY1305_AAD.length);
            cp.doFinal(PLAIN_TEXT);

            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
            cp.doFinal(PLAIN_TEXT);
            // Update AAD must be done before cipher update, or do final...
            cp.updateAAD(CHACHA20_POLY1305_AAD, 0, CHACHA20_POLY1305_AAD.length);
            fail("Did not get expected ProviderException(Failure in engineDoFinal)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.updateAAD(CHACHA20_POLY1305_AAD, 0, CHACHA20_POLY1305_AAD.length);
            fail("Did not get expected IllegalStateException(Cipher not initialized)");
        } catch (Exception e) {
        }

    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test using just doFinal calls
    //
    @Test
    public void testChaCha20Poly1305EncryptDecryptDoFinalWithoutAAD() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
            byte[] cipherText = cp.doFinal(PLAIN_TEXT);

            paramSpec = cp.getParameters().getParameterSpec(IvParameterSpec.class);

            // Verify the text
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, paramSpec);
            byte[] newPlainText = cp.doFinal(cipherText, 0, cipherText.length);

            assertTrue(Arrays.equals(PLAIN_TEXT, newPlainText));

        } catch (Exception e) {
            fail("Got unexpected exception on encrypt/decrypt...");
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test using just doFinal calls
    //
    @Test
    public void testChaCha20Poly1305EncryptDecryptDoFinalWithAAD() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
            cp.updateAAD(CHACHA20_POLY1305_AAD, 0, CHACHA20_POLY1305_AAD.length);
            byte[] cipherText = cp.doFinal(PLAIN_TEXT);

            paramSpec = cp.getParameters().getParameterSpec(IvParameterSpec.class);

            // Verify the text
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, paramSpec);
            cp.updateAAD(CHACHA20_POLY1305_AAD, 0, CHACHA20_POLY1305_AAD.length);
            byte[] newPlainText = cp.doFinal(cipherText, 0, cipherText.length);

            assertTrue(Arrays.equals(PLAIN_TEXT, newPlainText));

        } catch (Exception e) {
            fail("Got unexpected exception on encrypt/decrypt...");
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test using just doFinal calls
    //
    @Test
    public void testChaCha20Poly1305EncryptDecryptDoFinalWithoutAadBadTag() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
            byte[] cipherText = cp.doFinal(PLAIN_TEXT);
            System.arraycopy(BAD_TAG_16, 0, cipherText, cipherText.length - BAD_TAG_16.length,
                    BAD_TAG_16.length);

            paramSpec = cp.getParameters().getParameterSpec(IvParameterSpec.class);

            // Verify the text
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, paramSpec);
            cp.doFinal(cipherText, 0, cipherText.length);

            fail("Did not get expected ProviderException: Failure on doFinal(Bad Tag)");

        } catch (Exception e) {
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test using just doFinal calls
    //
    @Test
    public void testChaCha20Poly1305DecryptDoFinalWithAadNoTag() throws Exception {
        try {

            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
            cp.updateAAD(CHACHA20_POLY1305_AAD, 0, CHACHA20_POLY1305_AAD.length);
            cp.doFinal(PLAIN_TEXT);

            paramSpec = cp.getParameters().getParameterSpec(IvParameterSpec.class);

            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, paramSpec);
            cp.updateAAD(CHACHA20_POLY1305_AAD, 0, CHACHA20_POLY1305_AAD.length);
            cp.doFinal();

            fail("Did not get expected IllegalArgumentException(Missing tag on decrypt final)");

        } catch (Exception e) {
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test using just update, empty doFinal calls
    //
    @Test
    public void testChaCha20Poly1305EncryptDecryptUpdate() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
            byte[] cipherText1 = cp.update(PLAIN_TEXT);
            byte[] cipherText2 = cp.doFinal();

            paramSpec = cp.getParameters().getParameterSpec(IvParameterSpec.class);

            // Verify the text
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, paramSpec);
            byte[] newPlainText1 = (cipherText1 == null) ? new byte[0] : cp.update(cipherText1);
            byte[] newPlainText2 = cp.doFinal(cipherText2);

            int plainTextLength = (newPlainText1 == null) ? 0 : newPlainText1.length;
            byte[] newPlainText = new byte[plainTextLength + newPlainText2.length];

            if (plainTextLength != 0) {
                System.arraycopy(newPlainText1, 0, newPlainText, 0, plainTextLength);
            }
            System.arraycopy(newPlainText2, 0, newPlainText, plainTextLength, newPlainText2.length);

            assertTrue(Arrays.equals(PLAIN_TEXT, newPlainText));

        } catch (Exception e) {
            fail("Got unexpected exception on encrypt/decrypt...");
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test with partial update
    //
    @Test
    public void testChaCha20Poly1305EncryptDecryptPartialUpdate() throws Exception {
        int partialLen = PLAIN_TEXT.length > 10 ? 10 : 1;

        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
            byte[] cipherText1 = cp.update(PLAIN_TEXT, 0, partialLen);
            byte[] cipherText2 = cp.doFinal(PLAIN_TEXT, partialLen, PLAIN_TEXT.length - partialLen);

            paramSpec = cp.getParameters().getParameterSpec(IvParameterSpec.class);

            // Verify the text
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, paramSpec);
            byte[] newPlainText1 = (cipherText1 == null) ? new byte[0] : cp.update(cipherText1);
            byte[] newPlainText2 = cp.doFinal(cipherText2);

            int plainTextLength = (newPlainText1 == null) ? 0 : newPlainText1.length;
            byte[] newPlainText = new byte[plainTextLength + newPlainText2.length];

            if (plainTextLength != 0) {
                System.arraycopy(newPlainText1, 0, newPlainText, 0, plainTextLength);
            }
            System.arraycopy(newPlainText2, 0, newPlainText, plainTextLength, newPlainText2.length);

            assertTrue(Arrays.equals(PLAIN_TEXT, newPlainText));

        } catch (Exception e) {
            fail("Got unexpected exception on encrypt/decrypt...");
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt twice using same Cipher instance, same key, but different nonce
    //
    @Test
    public void testChaCha20Poly1305ReuseObjectSameKeyDifferentNonce() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
            byte[] cipherText1 = cp.doFinal(PLAIN_TEXT);

            paramSpec = cp.getParameters().getParameterSpec(IvParameterSpec.class);

            byte[] newNonce = Arrays.copyOf(NONCE_12_BYTE, NONCE_12_BYTE.length);
            newNonce[0]++;
            IvParameterSpec newNonceSpec = new IvParameterSpec(newNonce);
            // Verify that the cipher object can be used to encrypt again with same key different nonce
            cp.init(Cipher.ENCRYPT_MODE, key, newNonceSpec);
            byte[] cipherText2 = cp.doFinal(PLAIN_TEXT);

            boolean sameCipher = Arrays.equals(cipherText2, cipherText1);
            assertFalse(sameCipher, "Re-encrypted text with diffent nonce is same");
        } catch (Exception e) {
            fail("Got unexpected exception on encrypt/decrypt...");
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test using just doFinal calls (copy-safe)
    //
    @Test
    public void testChaCha20Poly1305EncryptDecryptDoFinalCopySafe() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);

            byte[] cipherText0 = cp.doFinal(PLAIN_TEXT);

            byte[] resultBuffer = Arrays.copyOf(PLAIN_TEXT, cp.getOutputSize(PLAIN_TEXT.length));
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
            int resultLen = cp.doFinal(resultBuffer, 0, PLAIN_TEXT.length, resultBuffer);
            byte[] cipherText = Arrays.copyOf(resultBuffer, resultLen);

            paramSpec = cp.getParameters().getParameterSpec(IvParameterSpec.class);;

            boolean success = Arrays.equals(cipherText, cipherText0);
            assertTrue(success, "Encrypted text does not match expected result");

            // Verify the text
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, paramSpec);
            resultBuffer = Arrays.copyOf(cipherText, cipherText.length);//cp.getOutputSize(cipherText.length));
            resultLen = cp.doFinal(resultBuffer, 0, cipherText.length, resultBuffer);
            byte[] newPlainText = Arrays.copyOf(resultBuffer, resultLen);

            success = Arrays.equals(newPlainText, PLAIN_TEXT);
            assertTrue(success, "Decrypted text does not match expected, msglen=" + PLAIN_TEXT.length);

        } catch (Exception e) {
            fail("Got unexpected exception on encrypt/decrypt...");
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test using just update, empty doFinal calls (copy-safe)
    //
    @Test
    public void testChaCha20Poly1305EncryptDecryptUpdateCopySafe() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);

            byte[] cipherText0 = cp.doFinal(PLAIN_TEXT);

            byte[] cipherText1 = Arrays.copyOf(PLAIN_TEXT, cp.getOutputSize(PLAIN_TEXT.length));
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
            int cipherText1Len = cp.update(cipherText1, 0, PLAIN_TEXT.length, cipherText1);
            byte[] cipherText2 = cp.doFinal();

            byte[] cipherText12 = new byte[cipherText1Len + cipherText2.length];
            System.arraycopy(cipherText1, 0, cipherText12, 0, cipherText1Len);
            System.arraycopy(cipherText2, 0, cipherText12, cipherText1Len, cipherText2.length);

            paramSpec = cp.getParameters().getParameterSpec(IvParameterSpec.class);

            boolean success = Arrays.equals(cipherText12, cipherText0);
            assertTrue(success, "Encrypted text does not match expected result");

            // Verify the text
            cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, paramSpec);

            byte[] plainText1 = Arrays.copyOf(cipherText12, cp.getOutputSize(cipherText12.length));
            int plainText1Len = cp.update(plainText1, 0, plainText1.length, plainText1);
            byte[] plainText2 = cp.doFinal(cipherText2);

            byte[] plainText12 = new byte[plainText1Len + plainText2.length];
            System.arraycopy(plainText1, 0, plainText12, 0, plainText1Len);
            System.arraycopy(plainText2, 0, plainText12, plainText1Len, plainText2.length);

            success = Arrays.equals(plainText12, PLAIN_TEXT);
            assertTrue(success, "Decrypted text does not match expected, msglen=" + PLAIN_TEXT.length);

        } catch (Exception e) {
            fail("Got unexpected exception on encrypt/decrypt...");
        }
    }
}
