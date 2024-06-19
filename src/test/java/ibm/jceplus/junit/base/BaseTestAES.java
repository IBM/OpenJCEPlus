/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Assume;

public class BaseTestAES extends BaseTestCipher {
    //--------------------------------------------------------------------------
    //
    //

    // 14 bytes: PASSED
    static final byte[] plainText14 = "12345678123456".getBytes();

    // 16 bytes: PASSED
    static final byte[] plainText16 = "1234567812345678".getBytes();

    // 18 bytes: PASSED
    static final byte[] plainText18 = "123456781234567812".getBytes();

    // 63 bytes: PASSED
    static final byte[] plainText63 = "123456781234567812345678123456781234567812345678123456781234567"
            .getBytes();

    // 128 bytes: PASSED
    static final byte[] plainText128 = "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            .getBytes();

    // 512, 65536, 524288 bytes, payload increment of 32 bytes (up to 16384 bytes) : PASSED
    Random r = new Random(5);
    static int iteration = 0;
    static final byte[] plainText512 = new byte[512];
    static final byte[] plainText65536 = new byte[65536];
    static final byte[] plainText524288 = new byte[524288];
    static final byte[] plainText1048576 = new byte[1048576];
    static final byte[] plainText16KB = new byte[16384];
    static final byte[] plainText = plainText128; // default value

    //--------------------------------------------------------------------------
    //
    //
    static boolean warmup = false;
    protected SecretKey key;
    protected AlgorithmParameters params = null;
    protected Cipher cp = null;
    protected boolean success = true;
    protected int specifiedKeySize = 0;

    //--------------------------------------------------------------------------
    //
    //
    public BaseTestAES(String providerName) {
        super(providerName);
        try {
            if (warmup == false) {
                warmup = true;
                warmup();
            }
        } catch (Exception e) {
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public BaseTestAES(String providerName, int keySize) throws Exception {
        super(providerName);
        this.specifiedKeySize = keySize;

        Assume.assumeTrue(javax.crypto.Cipher.getMaxAllowedKeyLength("AES") >= keySize);

        try {
            if (warmup == false) {
                warmup = true;
                warmup();
            }
        } catch (Exception e) {
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {
        byte[] encodedKey = new byte[(specifiedKeySize > 0 ? specifiedKeySize : 128) / 8];
        r.nextBytes(plainText512);
        r.nextBytes(plainText65536);
        r.nextBytes(plainText524288);
        r.nextBytes(plainText1048576);
        r.nextBytes(plainText16KB);
        r.nextBytes(encodedKey);
        key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    //--------------------------------------------------------------------------
    //
    //
    public void testAES() throws Exception {
        encryptDecrypt("AES");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CBC_ISO10126Padding() throws Exception {
        try {
            cp = Cipher.getInstance("AES/CBC/ISO10126Padding", providerName);
            fail(" NoSuchPaddingException is NOT thrown");
        } catch (NoSuchPaddingException e) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CBC_NoPadding() throws Exception {
        encryptDecrypt("AES/CBC/NoPadding", true, false);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CBC_PKCS5Padding() throws Exception {
        encryptDecrypt("AES/CBC/PKCS5Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CFB_ISO10126Padding() throws Exception {
        try {
            cp = Cipher.getInstance("AES/CFB/ISO10126Padding", providerName);
            fail(" NoSuchPaddingException is NOT thrown");
        } catch (NoSuchPaddingException e) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CFB8_NoPadding() throws Exception {
        encryptDecrypt("AES/CFB8/NoPadding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CFB_NoPadding() throws Exception {
        encryptDecrypt("AES/CFB/NoPadding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CFB8_PKCS5Padding() throws Exception {
        encryptDecrypt("AES/CFB8/PKCS5Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CFB_PKCS5Padding() throws Exception {
        encryptDecrypt("AES/CFB/PKCS5Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CFB128_ISO10126Padding() throws Exception {
        try {
            cp = Cipher.getInstance("AES/CFB128/ISO10126Padding", providerName);
            fail(" NoSuchPaddingException is NOT thrown");
        } catch (NoSuchPaddingException e) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CFB128_NoPadding() throws Exception {
        encryptDecrypt("AES/CFB128/NoPadding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CFB128_PKCS5Padding() throws Exception {
        encryptDecrypt("AES/CFB128/PKCS5Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CTR_ISO10126Padding() throws Exception {
        try {
            cp = Cipher.getInstance("AES/CTR/ISO10126Padding", providerName);
            fail(" NoSuchPaddingException is NOT thrown");
        } catch (NoSuchPaddingException e) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CTR_NoPadding() throws Exception {
        encryptDecrypt("AES/CTR/NoPadding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CTR_PKCS5Padding() throws Exception {
        encryptDecrypt("AES/CTR/PKCS5Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CTS_ISO10126Padding() throws Exception {
        try {
            cp = Cipher.getInstance("AES/CTS/ISO10126Padding", providerName);
            fail(" NoSuchAlgorithmException is NOT thrown");
        } catch (NoSuchAlgorithmException e) {
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CTS_NoPadding() throws Exception {
        try {
            cp = Cipher.getInstance("AES/CTS/NoPadding", providerName);
            fail(" NoSuchAlgorithmException is NOT thrown");
        } catch (NoSuchAlgorithmException e) {
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_CTS_PKCS5Padding() throws Exception {
        try {
            cp = Cipher.getInstance("AES/CTS/PKCS5Padding", providerName);
            fail(" NoSuchAlgorithmException is NOT thrown");
        } catch (NoSuchAlgorithmException e) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_ECB_ISO10126Padding() throws Exception {
        try {
            cp = Cipher.getInstance("AES/ECB/ISO10126Padding", providerName);
            fail(" NoSuchPaddingException is NOT thrown");
        } catch (NoSuchPaddingException e) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_ECB_NoPadding() throws Exception {
        encryptDecrypt("AES/ECB/NoPadding", true, false);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_ECB_PKCS5Padding() throws Exception {
        encryptDecrypt("AES/ECB/PKCS5Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_OFB_ISO10126Padding() throws Exception {
        try {
            cp = Cipher.getInstance("AES/OFB/ISO10126Padding", providerName);
            fail(" NoSuchPaddingException is NOT thrown");
        } catch (NoSuchPaddingException e) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_OFB_NoPadding() throws Exception {
        encryptDecrypt("AES/OFB/NoPadding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_OFB_PKCS5Padding() throws Exception {
        encryptDecrypt("AES/OFB/PKCS5Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_PCBC_ISO10126Padding() throws Exception {
        try {
            cp = Cipher.getInstance("AES/PCBC/ISO10126Padding", providerName);
            fail(" NoSuchAlgorithmException is NOT thrown");
        } catch (NoSuchAlgorithmException e) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_PCBC_NoPadding() throws Exception {
        try {
            cp = Cipher.getInstance("AES/PCBC/NoPadding", providerName);
            fail(" NoSuchAlgorithmException is NOT thrown");
        } catch (NoSuchAlgorithmException e) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAES_PCBC_PKCS5Padding() throws Exception {
        try {
            cp = Cipher.getInstance("AES/PCBC/PKCS5Padding", providerName);
            fail(" NoSuchAlgorithmException is NOT thrown");
        } catch (NoSuchAlgorithmException e) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAESShortBuffer() throws Exception {
        try {
            // Test AES Cipher
            cp = Cipher.getInstance("AES", providerName);

            // Encrypt the plain text
            cp.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = new byte[5];
            cp.doFinal(plainText, 0, plainText.length, cipherText);
            fail("Expected ShortBufferException did not occur");
        } catch (ShortBufferException ex) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAESIllegalBlockSizeEncrypt() throws Exception {
        try {
            cp = Cipher.getInstance("AES/CBC/NoPadding", providerName);

            int blockSize = cp.getBlockSize();
            byte[] message = new byte[blockSize - 1];

            // Encrypt the plain text
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(message);

            fail("Expected IllegalBlockSizeException did not occur");

        } catch (IllegalBlockSizeException ex) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAESIllegalBlockSizeDecrypt() throws Exception {
        try {
            cp = Cipher.getInstance("AES/CBC/PKCS5Padding", providerName);

            // Encrypt the plain text
            cp.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = cp.doFinal(plainText);
            params = cp.getParameters();

            // Verify the text
            cp.init(Cipher.DECRYPT_MODE, key, params);
            cp.doFinal(cipherText, 0, cipherText.length - 1);

            fail("Expected IllegalBlockSizeException did not occur");

        } catch (IllegalBlockSizeException ex) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAESBadPaddingDecrypt() throws NoSuchAlgorithmException, NoSuchProviderException,
            NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        try {
            cp = Cipher.getInstance("AES/CBC/PKCS5Padding", providerName);

            // Encrypt the plain text
            cp.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = cp.doFinal(plainText);
            params = cp.getParameters();
            // Create Bad Padding
            cipherText[cipherText.length - 1]++;
            // Verify the text

            cp.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText = cp.doFinal(cipherText, 0, cipherText.length);
            if (Arrays.equals(plainText, newPlainText)) {
                fail("Expected failure occur");
            } else {
                assertTrue(true);
            }

        } catch (BadPaddingException ex) {
            assertTrue(true);
        } catch (IllegalBlockSizeException e) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAESNoSuchAlgorithm() throws Exception {
        try {
            cp = Cipher.getInstance("AES/BBC/PKCS5Padding", providerName);
            fail("Expected NoSuchAlgorithmException did not occur");
        } catch (NoSuchAlgorithmException ex) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAESNull() throws Exception {
        cp = Cipher.getInstance("AES", providerName);
        SecretKey nullKey = null;

        try {
            cp.init(Cipher.ENCRYPT_MODE, nullKey);
            fail("Expected InvalidKeyException did not occur");
        } catch (InvalidKeyException e) {
        }

        try {
            //cp.init(Cipher.ENCRYPT_MODE, nullKey, SecureRandom.getInstance("IBMSecureRandom"));
            cp.init(Cipher.ENCRYPT_MODE, nullKey, SecureRandom.getInstance("SHA2DRBG"));
            fail("Expected InvalidKeyException did not occur");
        } catch (InvalidKeyException e) {
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testIllegalParamSpec() throws Exception {
        cp = Cipher.getInstance("AES/CBC/PKCS5Padding", providerName);

        try {
            byte[] iv = null;
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cp.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            fail("Expected NullPointerException or InvalidAlgorithmParameterException");
        } catch (NullPointerException npe) {
        } catch (InvalidAlgorithmParameterException e) {
        }

        try {
            byte[] iv = {0, 1, 2, 3, 4, 5, 6, 7};
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cp.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            fail("Expected InvalidAlgorithmParameterException");
        } catch (InvalidAlgorithmParameterException e) {
        }

        try {
            byte[] iv = {0, 1, 2, 3, 4, 5, 6, 7, 8};
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cp.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            fail("Expected InvalidAlgorithmParameterException");
        } catch (InvalidAlgorithmParameterException e) {
        }

        try {
            byte[] iv = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cp.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        } catch (InvalidAlgorithmParameterException e) {
            fail("Got unexpected InvalidAlgorithmParameterException");
        }

        try {
            byte[] iv = {0, 1, 2, 3, 4, 5, 6, 7};
            RC5ParameterSpec ivSpec = new RC5ParameterSpec(0, 0, 0, iv);
            cp.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            fail("Expected InvalidAlgorithmParameterException");
        } catch (InvalidAlgorithmParameterException e) {
        }

        try {
            int iv = 8;
            RC2ParameterSpec ivSpec = new RC2ParameterSpec(iv);
            cp.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            fail("Expected InvalidAlgorithmParameterException");
        } catch (InvalidAlgorithmParameterException e) {
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testArguments() throws Exception {
        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0]);
        } catch (Exception e) {
            fail("Did not expect exception on doFinal(new byte[0], 0, 0)");
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 1);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0);
            fail("Did not get expected ShortBufferException on doFinal(new byte[0], 0)");
        } catch (ShortBufferException e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 1);
            fail("Should have gotten exception on doFinal(new byte[0], 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[cp.getOutputSize(0)], 1);
            fail("Expected ShortBufferException");
        } catch (ShortBufferException e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 1, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0, 1);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0);
        } catch (Exception e) {
            fail("Got unexpected exception on doFinal(new byte[0], 0, 0)");
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 1, 0);
            fail("Did not get expected exception on doFinal(new byte[0], 1, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 1);
            fail("Did not get expected exception on doFinal(new byte[0], 0, 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0, 0, null);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0, new byte[0]);
            fail("Did not get expected ShortBufferException on doFinal(new byte[0], 0, 9, new byte[0])");
        } catch (ShortBufferException e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0, null, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0, new byte[0], 0);
            fail("Did not get expected ShortBufferException on doFinal(new byte[0], 0, 0, new byte[0], 0)");
        } catch (ShortBufferException e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0]);
        } catch (Exception e) {
            fail("Got unexpected exception on update( new byte[0])");
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 1, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 1);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0);
        } catch (Exception e) {
            fail("Got unexpected exception on update(new byte[0], 0, 0)");
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 1, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 1);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 0, null);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 0, new byte[0]);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, new byte[0]);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null, 1);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("AES", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, new byte[0], 0);
        } catch (Exception e) {
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    protected boolean encryptDecrypt(Cipher cp) throws Exception {
        cp.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cp.doFinal(plainText);
        params = cp.getParameters();

        // Verify the text
        cp.init(Cipher.DECRYPT_MODE, key, params);
        byte[] newPlainText = cp.doFinal(cipherText, 0, cipherText.length);

        return Arrays.equals(plainText, newPlainText);
    }

    //--------------------------------------------------------------------------
    //
    //
    protected void encryptDecrypt(String algorithm) throws Exception {
        encryptDecrypt(algorithm, false, false);
    }

    //--------------------------------------------------------------------------
    //
    //
    protected void encryptDecrypt(String algorithm, boolean requireLengthMultipleBlockSize,
            boolean testFinalizeOnly) throws Exception {
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, null, testFinalizeOnly);
    }

    //--------------------------------------------------------------------------
    //
    //
    protected void encryptDecrypt(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams, boolean testFinalizeOnly) throws Exception {
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText14,
                testFinalizeOnly);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText16,
                testFinalizeOnly);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText18,
                testFinalizeOnly);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText63,
                testFinalizeOnly);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText128,
                testFinalizeOnly);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText512,
                testFinalizeOnly);
        for (iteration = 32; iteration <= 16384; iteration += 32) {
            byte[] slice = Arrays.copyOfRange(plainText16KB, 0, iteration);
            encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, slice,
                    testFinalizeOnly);
        }
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText65536,
                testFinalizeOnly);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText524288,
                testFinalizeOnly);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText1048576,
                testFinalizeOnly);
    }

    //--------------------------------------------------------------------------
    //
    //
    protected void encryptDecrypt(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams, byte[] message, boolean testFinalizeOnly)
            throws Exception {
        if (testFinalizeOnly) {
            encryptDecryptDoFinal(algorithm, requireLengthMultipleBlockSize, algParams, message);
            encryptDecryptReuseObject(algorithm, requireLengthMultipleBlockSize, algParams,
                    message);
            encryptDecryptDoFinalCopySafe(algorithm, requireLengthMultipleBlockSize, algParams,
                    message);
        } else {
            encryptDecryptDoFinal(algorithm, requireLengthMultipleBlockSize, algParams, message);
            encryptDecryptUpdate(algorithm, requireLengthMultipleBlockSize, algParams, message);
            encryptDecryptPartialUpdate(algorithm, requireLengthMultipleBlockSize, algParams,
                    message);
            encryptDecryptReuseObject(algorithm, requireLengthMultipleBlockSize, algParams,
                    message);
            encryptDecryptDoFinalCopySafe(algorithm, requireLengthMultipleBlockSize, algParams,
                    message);
            encryptDecryptUpdateCopySafe(algorithm, requireLengthMultipleBlockSize, algParams,
                    message);
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test using just doFinal calls
    //
    protected void encryptDecryptDoFinal(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams, byte[] message) throws Exception

    {
        cp = Cipher.getInstance(algorithm, providerName);
        if (algParams == null) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cp.getBlockSize();
        try {
            byte[] cipherText = cp.doFinal(message);
            params = cp.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length,
                        ((blockSize > 0) && (message.length % blockSize) == 0));
            }

            // Verify the text
            cp.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText = cp.doFinal(cipherText);

            boolean success = Arrays.equals(newPlainText, message);
            assertTrue("Decrypted text does not match expected, msglen=" + message.length, success);

            // Verify the text again
            cp.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText2 = cp.doFinal(cipherText, 0, cipherText.length);
            success = Arrays.equals(newPlainText2, message);
            assertTrue("Decrypted text does not match expected, msglen=" + message.length, success);
        } catch (IllegalBlockSizeException e) {
            assertTrue(
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length,
                    (!requireLengthMultipleBlockSize || (message.length % blockSize) != 0));
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test using just update, empty doFinal calls
    //
    protected void encryptDecryptUpdate(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams, byte[] message) throws Exception {
        cp = Cipher.getInstance(algorithm, providerName);
        if (algParams == null) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cp.getBlockSize();
        try {
            byte[] cipherText1 = cp.update(message);
            byte[] cipherText2 = cp.doFinal();
            params = cp.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length,
                        ((message.length % blockSize) == 0));
            }

            // Verify the text
            cp.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText1 = (cipherText1 == null) ? new byte[0] : cp.update(cipherText1);
            byte[] newPlainText2 = cp.doFinal(cipherText2);

            int l = (newPlainText1 == null) ? 0 : newPlainText1.length;
            byte[] newPlainText = new byte[l + newPlainText2.length];

            if (l != 0) {
                System.arraycopy(newPlainText1, 0, newPlainText, 0, l);
            }
            System.arraycopy(newPlainText2, 0, newPlainText, l, newPlainText2.length);

            boolean success = Arrays.equals(newPlainText, message);
            assertTrue("Decrypted text does not match expected, msglen=" + message.length, success);
        } catch (IllegalBlockSizeException e) {
            assertTrue(
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length,
                    (!requireLengthMultipleBlockSize || (message.length % blockSize) != 0));
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test with partial update
    //
    protected void encryptDecryptPartialUpdate(String algorithm,
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message)
            throws Exception {
        cp = Cipher.getInstance(algorithm, providerName);
        if (algParams == null) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cp.getBlockSize();
        int partialLen = message.length > 10 ? 10 : 1;
        try {
            byte[] cipherText1 = cp.update(message, 0, partialLen);
            byte[] cipherText2 = cp.doFinal(message, partialLen, message.length - partialLen);
            params = cp.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length,
                        ((message.length % blockSize) == 0));
            }

            // Verify the text
            cp.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText1 = (cipherText1 == null) ? new byte[0] : cp.update(cipherText1);
            byte[] newPlainText2 = cp.doFinal(cipherText2);

            int l = (newPlainText1 == null) ? 0 : newPlainText1.length;
            byte[] newPlainText = new byte[l + newPlainText2.length];

            if (l != 0) {
                System.arraycopy(newPlainText1, 0, newPlainText, 0, l);
            }
            System.arraycopy(newPlainText2, 0, newPlainText, l, newPlainText2.length);

            boolean success = Arrays.equals(newPlainText, message);
            assertTrue("Decrypted text does not match expected, partial msglen=" + message.length,
                    success);
        } catch (IllegalBlockSizeException e) {
            assertTrue(
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length,
                    (!requireLengthMultipleBlockSize || (message.length % blockSize) != 0));
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test reusing cipher object
    //
    protected void encryptDecryptReuseObject(String algorithm,
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message)
            throws Exception

    {
        cp = Cipher.getInstance(algorithm, providerName);
        if (algParams == null) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cp.getBlockSize();
        try {
            byte[] cipherText = cp.doFinal(message);
            params = cp.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length,
                        ((blockSize > 0) && (message.length % blockSize) == 0));
            }

            // Verify that the cipher object can be used to encrypt again without re-init
            byte[] cipherText2 = cp.doFinal(message);
            boolean success = Arrays.equals(cipherText2, cipherText);
            assertTrue("Re-encrypted text does not match", success);

            // Verify the text
            cp.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText = cp.doFinal(cipherText);
            success = Arrays.equals(newPlainText, message);
            assertTrue("Decrypted text does not match expected, msglen=" + message.length, success);

            // Verify that the cipher object can be used to decrypt again without re-init
            byte[] newPlainText2 = cp.doFinal(cipherText, 0, cipherText.length);
            success = Arrays.equals(newPlainText2, newPlainText);
            assertTrue("Re-decrypted text does not match", success);
        } catch (IllegalBlockSizeException e) {
            assertTrue(
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length,
                    (!requireLengthMultipleBlockSize || (message.length % blockSize) != 0));
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test using just doFinal calls (copy-safe)
    //
    protected void encryptDecryptDoFinalCopySafe(String algorithm,
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message)
            throws Exception

    {
        cp = Cipher.getInstance(algorithm, providerName);
        if (algParams == null) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cp.getBlockSize();
        try {
            byte[] cipherText0 = cp.doFinal(message);

            byte[] resultBuffer = Arrays.copyOf(message, cp.getOutputSize(message.length));
            int resultLen = cp.doFinal(resultBuffer, 0, message.length, resultBuffer);
            byte[] cipherText = Arrays.copyOf(resultBuffer, resultLen);
            params = cp.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length,
                        ((blockSize > 0) && (message.length % blockSize) == 0));
            }

            boolean success = Arrays.equals(cipherText, cipherText0);
            assertTrue("Encrypted text does not match expected result", success);

            // Verify the text
            cp.init(Cipher.DECRYPT_MODE, key, params);
            resultBuffer = Arrays.copyOf(cipherText, cipherText.length);//cp.getOutputSize(cipherText.length));
            resultLen = cp.doFinal(resultBuffer, 0, cipherText.length, resultBuffer);
            byte[] newPlainText = Arrays.copyOf(resultBuffer, resultLen);

            success = Arrays.equals(newPlainText, message);
            assertTrue("Decrypted text does not match expected, msglen=" + message.length, success);
        } catch (IllegalBlockSizeException e) {
            assertTrue(
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length,
                    (!requireLengthMultipleBlockSize || (message.length % blockSize) != 0));
        }
    }

    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test using just update, empty doFinal calls (copy-safe)
    //
    protected void encryptDecryptUpdateCopySafe(String algorithm,
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message)
            throws Exception

    {
        cp = Cipher.getInstance(algorithm, providerName);
        if (algParams == null) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cp.getBlockSize();
        try {
            byte[] cipherText0 = cp.doFinal(message);

            byte[] resultBuffer = Arrays.copyOf(message, cp.getOutputSize(message.length));
            int cipherText1Len = cp.update(resultBuffer, 0, message.length, resultBuffer);
            byte[] cipherText2 = cp.doFinal();

            byte[] cipherText = new byte[cipherText1Len + cipherText2.length];
            System.arraycopy(resultBuffer, 0, cipherText, 0, cipherText1Len);
            System.arraycopy(cipherText2, 0, cipherText, cipherText1Len, cipherText2.length);
            params = cp.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length,
                        ((blockSize > 0) && (message.length % blockSize) == 0));
            }

            boolean success = Arrays.equals(cipherText, cipherText0);
            assertTrue("Encrypted text does not match expected result", success);

            // Verify the text
            cp.init(Cipher.DECRYPT_MODE, key, params);
            resultBuffer = Arrays.copyOf(cipherText, cp.getOutputSize(cipherText.length));
            int plainText1Len = cp.update(resultBuffer, 0, cipherText.length, resultBuffer);
            byte[] plainText2 = cp.doFinal();

            byte[] newPlainText = new byte[plainText1Len + plainText2.length];
            System.arraycopy(resultBuffer, 0, newPlainText, 0, plainText1Len);
            System.arraycopy(plainText2, 0, newPlainText, plainText1Len, plainText2.length);

            success = Arrays.equals(newPlainText, message);
            assertTrue("Decrypted text does not match expected, msglen=" + message.length, success);
        } catch (IllegalBlockSizeException e) {
            assertTrue(
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length,
                    (!requireLengthMultipleBlockSize || (message.length % blockSize) != 0));
        }
    }


    //--------------------------------------------------------------------------
    // warmup functions for enable fastjni
    //
    static public void warmup() throws Exception {
        java.security.Provider java_provider = null;
        int modeInt;
        boolean stream = false;
        SecretKeySpec skey;
        int key_size = 128;
        byte[] skey_bytes = new byte[key_size / 8];
        int len = 4096;
        byte[] iv;
        byte[] data = plainText16;
        byte[] out;
        Cipher cipher;
        Random r;
        try {
            java_provider = java.security.Security.getProvider("OpenJCEPlus");
            if (java_provider == null) {
                java_provider = new com.ibm.crypto.plus.provider.OpenJCEPlus();
                java.security.Security.insertProviderAt(java_provider, 1);
            }

            r = new Random(10);
            String mode = "encrypt_stream";
            String cipherMode = "AES/CBC/NoPadding";

            if (mode.contains("encrypt"))
                modeInt = 1;
            else if (mode.contains("decrypt"))
                modeInt = 0;
            else
                throw new RuntimeException("Unsupported mode");

            if (mode.contains("block"))
                stream = false;
            else if (mode.contains("stream"))
                stream = true;
            else
                throw new RuntimeException("block mode or stream mode must be specified");

            r.nextBytes(skey_bytes);
            skey = new SecretKeySpec(skey_bytes, "AES");


            for (int i = 0; i < 999999; i++) {
                cipher = Cipher.getInstance(cipherMode, java_provider);
                out = new byte[len];
                iv = new byte[16];
                r.nextBytes(iv);
                AlgorithmParameterSpec iviv = new IvParameterSpec(iv);

                if (modeInt == 0)
                    cipher.init(Cipher.DECRYPT_MODE, skey, iviv);
                else
                    cipher.init(Cipher.ENCRYPT_MODE, skey, iviv);
                if (stream) {
                    for (long j = 0; j < 9; j++)
                        cipher.update(data, 0, data.length, out);
                } else {
                    for (long k = 0; k < 9; k++) {
                        cipher.update(data, 0, data.length, out);
                        // cipher.doFinal();
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public void testUpdateForAES_CBC_PKCS5Padding() throws Exception {

        try {
            byte[] iv = new byte[16];
            Arrays.fill(iv, (byte) 0);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            byte[] key = new byte[16];
            Arrays.fill(key, (byte) 1);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", providerName);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] plain = new byte[10000];
            Arrays.fill(plain, (byte) 1);

            ByteBuffer buffer = ByteBuffer.allocate(cipher.getOutputSize(plain.length));
            clearUpdateForAES_CBC_PKCS5Padding(buffer);
            addDataUpdateForAES_CBC_PKCS5Padding(buffer, plain, plain.length);
            encodeDataForAES_CBC_PKCS5Padding(buffer, cipher);
            assertTrue(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false);
        }
    }

    private void setDataUpdateForAES_CBC_PKCS5Padding(ByteBuffer buffer, byte[] data, int pos,
            int len) {
        buffer.position(pos);
        buffer.put(data, 0, len);

        buffer.rewind();
    }

    private void addDataUpdateForAES_CBC_PKCS5Padding(ByteBuffer buffer, byte[] data, int len) {
        int dataEnd = buffer.limit();

        buffer.limit(dataEnd + len);

        setDataUpdateForAES_CBC_PKCS5Padding(buffer, data, dataEnd, len);
    }

    private void clearUpdateForAES_CBC_PKCS5Padding(ByteBuffer buffer) {
        buffer.position(0);
        buffer.limit(0);
    }

    private void encodeDataForAES_CBC_PKCS5Padding(ByteBuffer buffer, Cipher cipher)
            throws IllegalBlockSizeException, ShortBufferException, BadPaddingException {
        int dataSize = buffer.limit();
        buffer.limit(buffer.capacity());

        int srcIndex = 0;
        int cnvIndex = 0;
        final int buff_size = 1024;
        byte[] tempIn = new byte[buff_size];
        byte[] tempOut = new byte[buff_size];

        while (srcIndex < dataSize) {
            int length;
            if (srcIndex + buff_size < dataSize) {
                length = buff_size;
            } else {
                length = dataSize - srcIndex;
            }
            buffer.position(srcIndex);
            buffer.get(tempIn, 0, length);

            int cnvLen = cipher.update(tempIn, 0, length, tempOut);

            buffer.position(cnvIndex);
            buffer.put(tempOut, 0, cnvLen);

            srcIndex += length;
            cnvIndex += cnvLen;
        }
        int cnvLen = cipher.doFinal(tempOut, 0);

        buffer.position(cnvIndex);
        buffer.put(tempOut, 0, cnvLen);

        buffer.flip();
    }

}
