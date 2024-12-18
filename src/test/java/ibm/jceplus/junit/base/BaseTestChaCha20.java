/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import com.ibm.crypto.plus.provider.ChaCha20Constants;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestChaCha20 extends BaseTestCipher implements ChaCha20Constants {


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
    static final byte[] NONCE_13_BYTE = "1234567812345".getBytes();

    static final int COUNTER_0 = 0;
    static final int COUNTER_1 = 1;
    static final int COUNTER_MIN = Integer.MIN_VALUE;
    static final int COUNTER_MAX = Integer.MAX_VALUE;

    static final String CHACHA20_ALGORITHM = "ChaCha20";

    static final ChaCha20ParameterSpec CHACHA20_PARAM_SPEC_COUNTER_0 = new ChaCha20ParameterSpec(
            NONCE_12_BYTE, COUNTER_0);
    static final ChaCha20ParameterSpec CHACHA20_PARAM_SPEC_COUNTER_1 = new ChaCha20ParameterSpec(
            NONCE_12_BYTE, COUNTER_1);
    static final ChaCha20ParameterSpec CHACHA20_PARAM_SPEC_COUNTER_MIN = new ChaCha20ParameterSpec(
            NONCE_12_BYTE, COUNTER_MIN);
    static final ChaCha20ParameterSpec CHACHA20_PARAM_SPEC_COUNTER_MAX = new ChaCha20ParameterSpec(
            NONCE_12_BYTE, COUNTER_MAX);


    protected KeyGenerator keyGen = null;
    protected SecretKey key = null;
    protected SecretKeyFactory keyFactory = null;
    protected ChaCha20ParameterSpec paramSpec = null;
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
    public void testChaCha20KeyFactory() throws Exception {

        try {
            keyFactory = SecretKeyFactory.getInstance(CHACHA20_ALGORITHM, getProviderName());
        } catch (Exception e) {
            fail("Got unexpected exception on ChaCha20KeyFactory.getInstance()...");
        }
    }

    @Test
    public void testChaCha20IllegalKeyNonceReuse() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_PARAM_SPEC_COUNTER_0);
            cp.init(Cipher.DECRYPT_MODE, key, CHACHA20_PARAM_SPEC_COUNTER_0);

            //fail("Expected InvalidKeyException did not occur");

        } catch (InvalidKeyException e) {
            assertTrue(false);
        }
    }

    @Test
    public void testChaCha20ShortBuffer() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());

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
    public void testChaCha20GetBlockSizeEncryptDecrypt() throws Exception {
        chaCha20GetBlockSize(Cipher.ENCRYPT_MODE);
        chaCha20GetBlockSize(Cipher.DECRYPT_MODE);
    }


    public void chaCha20GetBlockSize(int opMode) throws Exception {
        ChaCha20ParameterSpec chaCha20ParamSpec = new ChaCha20ParameterSpec(NONCE_12_BYTE, 0);
        cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
        cp.init(opMode, key, chaCha20ParamSpec);
        assertTrue((cp.getBlockSize() == ChaCha20_BLOCK_SIZE), "ChaCha20 Block size must be: " + ChaCha20_BLOCK_SIZE);
    }

    @Test
    public void testChaCha20ValidTransformations() throws Exception {
        String transformation = null;
        try {
            transformation = CHACHA20_ALGORITHM;
            cp = Cipher.getInstance(transformation, getProviderName());
            transformation = "ChaCha20/None/NoPadding";
            cp = Cipher.getInstance(transformation, getProviderName());
        } catch (NoSuchAlgorithmException ex) {
            fail("NoSuchAlgorithmException occurred for transform: " + transformation);
        }
    }

    @Test
    public void testChaCha20InvalidTransformation() throws Exception {
        String transformation = "BogusChaCha20/BogusMode/BogusPadding";
        try {
            cp = Cipher.getInstance(transformation, getProviderName());
            fail("Expected NoSuchAlgorithmException did not occur");
        } catch (NoSuchAlgorithmException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testChaCha20NullKey() throws Exception {
        cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
        SecretKey nullKey = null;

        try {
            cp.init(Cipher.ENCRYPT_MODE, nullKey);
            fail("Expected InvalidKeyException did not occur");
        } catch (InvalidKeyException e) {
        }

        try {
            //cp.init(Cipher.ENCRYPT_MODE, nullKey, SecureRandom.getInstance("SecureRandom"));
            cp.init(Cipher.ENCRYPT_MODE, nullKey, SecureRandom.getInstance("SHA2DRBG"));
            fail("Expected InvalidKeyException did not occur");
        } catch (InvalidKeyException e) {
        }
    }

    @Test
    public void testChaCha20NoParamSpec() throws Exception {

        try {
            // For ChaCha20 you need to pass in the nonce/iv because
            // there is no way to get the iv out from this cipher.
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(PLAIN_TEXT);

        } catch (Exception e) {
            fail("Got unexpected exception on encrypt/decrypt...");
        }
    }

    @Test
    public void testChaCha20NullParamSpec() throws Exception {

        try {
            // For ChaCha20 you need to pass in the nonce/iv because
            // there is no way to get the iv out from this cipher.
            ChaCha20ParameterSpec chaCha20pec = null;
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, chaCha20pec);
            cp.doFinal(PLAIN_TEXT);
        } catch (Exception e) {
            fail("Got unexpected exception on encrypt/decrypt...");
        }
    }

    @Test
    public void testChaCha20InvalidParamSpec() throws Exception {

        try {
            byte[] iv = null;
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            fail("Expected NullPointerException or InvalidAlgorithmParameterException");
        } catch (NullPointerException npe) {
        } catch (InvalidAlgorithmParameterException e) {
        }

        try {
            byte[] iv = null;
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, ivSpec);
            fail("Expected NullPointerException or InvalidAlgorithmParameterException");
        } catch (NullPointerException npe) {
        } catch (InvalidAlgorithmParameterException e) {
        }

        try {
            ChaCha20ParameterSpec chaCha20pec = new ChaCha20ParameterSpec(NONCE_11_BYTE, COUNTER_1);
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, chaCha20pec);
            fail("Expected NullPointerException or InvalidAlgorithmParameterException");
        } catch (NullPointerException npe) {
        } catch (IllegalArgumentException e) {
        }

        try {
            ChaCha20ParameterSpec chaCha20pec = new ChaCha20ParameterSpec(NONCE_13_BYTE, COUNTER_1);
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, chaCha20pec);
            fail("Expected NullPointerException or InvalidAlgorithmParameterException");
        } catch (NullPointerException npe) {
        } catch (IllegalArgumentException e) {
        }
    }

    @Test
    public void testChaCha20EncryptUpdateAndDoFinalArguments() throws Exception {

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.doFinal(new byte[0]);
            fail("Did not get expected IllegalStateException(Cipher not initialized)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null);
            fail("Did not get expected IllegalArgumentException on doFinal(null)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0]);
        } catch (Exception e) {
            fail("Did not expect exception on doFinal(new byte[0])");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0);
            fail("Did not get expected IllegalArgumentException on doFinal(null, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 1);
            fail("Did not get expected IllegalArgumentException on doFinal(null, 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0);
        } catch (ShortBufferException e) {
            fail("Did not expect exception on doFinal(new byte[0], 0)");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 1);
            fail("Did not get expected IllegalArgumentException on doFinal(new byte[0], 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[cp.getOutputSize(0)], 1);
            fail("Did not get expected IllegalArgumentException on doFinal(new byte[cp.getOutputSize(0)], 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0, 0);
            fail("Did not get expected IllegalArgumentException on doFinal(null, 0, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 1, 0);
            fail("Did not get expected IllegalArgumentException on doFinal(null, 1, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0, 1);
            fail("Did not get expected IllegalArgumentException on doFinal(null, 0, 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0);
        } catch (Exception e) {
            fail("Got unexpected exception on doFinal(new byte[0], 0, 0)");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 1, 0);
            fail("Did not get expected IllegalArgumentException on doFinal(new byte[0], 1, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 1);
            fail("Did not get expected IllegalArgumentException on doFinal(new byte[0], 0, 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0, 0, null);
            fail("Did not get expected IllegalArgumentException on doFinal(new byte[0], 0, 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0, new byte[0]);
        } catch (Exception e) {
            fail("Got unexpected exception on doFinal(new byte[0], 0, 0, new byte[0])");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0, null, 0);
            fail("Did not get expected IllegalArgumentException on doFinal(new byte[0], 0, 0, null, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0, new byte[0], 0);
        } catch (Exception e) {
            fail("Got unexpected exception on doFinal(new byte[0], 0, 0, new byte[0], 0)");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.update(new byte[0]);
            fail("Did not get expected IllegalStateException(Cipher not initialized)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null);
            fail("Did not get expected IllegalArgumentException on update(null)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0]);
        } catch (Exception e) {
            fail("Got unexpected exception on update(new byte[0])");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 0);
            fail("Did not get expected IllegalArgumentException on update(null, 0, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 1, 0);
            fail("Did not get expected IllegalArgumentException on update(null, 1, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 1);
            fail("Did not get expected IllegalArgumentException on update(null, 0, 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0);
        } catch (Exception e) {
            fail("Got unexpected exception on update(new byte[0], 0, 0)");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 1, 0);
            fail("Did not get expected IllegalArgumentException on update(new byte[0], 1, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 1);
            fail("Did not get expected IllegalArgumentException on update(new byte[0], 0, 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 0, null);
            fail("Did not get expected IllegalArgumentException on update(null, 0, 0, null)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 0, new byte[0]);
            fail("Did not get expected IllegalArgumentException on update(null, 0, 0, new byte[0])");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null);
        } catch (Exception e) {
            fail("Did not expect exception on update(new byte[0], 0, 0, null)");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, new byte[0]);
        } catch (Exception e) {
            fail("Did not expect exception on update(new byte[0], 0, 0, new byte[0])");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null, 0);
        } catch (Exception e) {
            fail("Did not expect exception on update(new byte[0], 0, 0, null, 0)");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null, 1);
        } catch (Exception e) {
            fail("Did not expect exception on update(new byte[0], 0, 0, null, 1)");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, new byte[0], 0);
        } catch (Exception e) {
            fail("Did not expect exception on update(new byte[0], 0, 0, new byte[0], 0)");
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test using MIN/MAX counter values
    //
    @Test
    public void testChaCha20EncryptDecryptMinMaxCounter() throws Exception {

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_PARAM_SPEC_COUNTER_MIN);
            byte[] cipherText = cp.doFinal(PLAIN_TEXT);

            paramSpec = CHACHA20_PARAM_SPEC_COUNTER_MIN;

            // Verify the text
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, paramSpec);
            byte[] newPlainText = cp.doFinal(cipherText, 0, cipherText.length);

            assertTrue(Arrays.equals(PLAIN_TEXT, newPlainText));

        } catch (Exception e) {
            fail("Got unexpected exception on MIN counter value...");
        }

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_PARAM_SPEC_COUNTER_MAX);
            byte[] cipherText = cp.doFinal(PLAIN_TEXT);

            paramSpec = CHACHA20_PARAM_SPEC_COUNTER_MAX;

            // Verify the text
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, paramSpec);
            byte[] newPlainText = cp.doFinal(cipherText, 0, cipherText.length);

            assertTrue(Arrays.equals(PLAIN_TEXT, newPlainText));

        } catch (Exception e) {
            fail("Got unexpected exception on MAX counter value...");
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test using just doFinal calls
    //
    @Test
    public void testChaCha20EncryptDecryptDoFinal() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_PARAM_SPEC_COUNTER_0);
            byte[] cipherText = cp.doFinal(PLAIN_TEXT);

            paramSpec = CHACHA20_PARAM_SPEC_COUNTER_0;

            // Verify the text
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, paramSpec);
            byte[] newPlainText = cp.doFinal(cipherText, 0, cipherText.length);

            assertTrue(Arrays.equals(PLAIN_TEXT, newPlainText));

        } catch (Exception e) {
            fail("Got unexpected exception on encrypt/decrypt...");
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test using just update, empty doFinal calls
    //
    @Test
    public void testChaCha20EncryptDecryptUpdate() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_PARAM_SPEC_COUNTER_1);
            byte[] cipherText1 = cp.update(PLAIN_TEXT);
            byte[] cipherText2 = cp.doFinal();

            paramSpec = CHACHA20_PARAM_SPEC_COUNTER_1;

            // Verify the text
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
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
    public void testChaCha20EncryptDecryptPartialUpdate() throws Exception {
        int partialLen = PLAIN_TEXT.length > 10 ? 10 : 1;

        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_PARAM_SPEC_COUNTER_0);
            byte[] cipherText1 = cp.update(PLAIN_TEXT, 0, partialLen);
            byte[] cipherText2 = cp.doFinal(PLAIN_TEXT, partialLen, PLAIN_TEXT.length - partialLen);

            paramSpec = CHACHA20_PARAM_SPEC_COUNTER_0;

            // Verify the text
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
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
    public void testChaCha20ReuseObjectSameKeyDifferentNonce() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_PARAM_SPEC_COUNTER_0);
            byte[] cipherText1 = cp.doFinal(PLAIN_TEXT);

            paramSpec = CHACHA20_PARAM_SPEC_COUNTER_0;
            byte[] newNonce = Arrays.copyOf(NONCE_12_BYTE, NONCE_12_BYTE.length);
            newNonce[0]++;
            ChaCha20ParameterSpec newNonceSpec = new ChaCha20ParameterSpec(newNonce, COUNTER_0);
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
    public void testChaCha20EncryptDecryptDoFinalCopySafe() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_PARAM_SPEC_COUNTER_0);

            byte[] cipherText0 = cp.doFinal(PLAIN_TEXT);

            byte[] resultBuffer = Arrays.copyOf(PLAIN_TEXT, cp.getOutputSize(PLAIN_TEXT.length));
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_PARAM_SPEC_COUNTER_0);
            int resultLen = cp.doFinal(resultBuffer, 0, PLAIN_TEXT.length, resultBuffer);
            byte[] cipherText = Arrays.copyOf(resultBuffer, resultLen);

            paramSpec = CHACHA20_PARAM_SPEC_COUNTER_0;

            boolean success = Arrays.equals(cipherText, cipherText0);
            assertTrue(success, "Encrypted text does not match expected result");

            // Verify the text
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
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
    public void testChaCha20EncryptDecryptUpdateCopySafe() throws Exception {
        try {
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_PARAM_SPEC_COUNTER_0);

            byte[] cipherText0 = cp.doFinal(PLAIN_TEXT);

            byte[] cipherText1 = Arrays.copyOf(PLAIN_TEXT, cp.getOutputSize(PLAIN_TEXT.length));
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_PARAM_SPEC_COUNTER_0);
            int cipherText1Len = cp.update(cipherText1, 0, PLAIN_TEXT.length, cipherText1);
            byte[] cipherText2 = cp.doFinal();

            byte[] cipherText12 = new byte[cipherText1Len + cipherText2.length];
            System.arraycopy(cipherText1, 0, cipherText12, 0, cipherText1Len);
            System.arraycopy(cipherText2, 0, cipherText12, cipherText1Len, cipherText2.length);

            // You can not get the parameters for ChaCha20
            paramSpec = CHACHA20_PARAM_SPEC_COUNTER_0;

            boolean success = Arrays.equals(cipherText12, cipherText0);
            assertTrue(success, "Encrypted text does not match expected result");

            // Verify the text
            cp = Cipher.getInstance(CHACHA20_ALGORITHM, getProviderName());
            cp.init(Cipher.DECRYPT_MODE, key, paramSpec);

            byte[] plainText1 = Arrays.copyOf(cipherText12, cp.getOutputSize(cipherText12.length));
            int plainText1Len = cp.update(plainText1, 0, cipherText12.length, plainText1);
            byte[] plainText2 = cp.doFinal();

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
