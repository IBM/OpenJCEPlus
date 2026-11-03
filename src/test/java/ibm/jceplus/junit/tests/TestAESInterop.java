/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import ibm.jceplus.junit.base.BaseUtils;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Tag(Tags.OPENJCEPLUS_OCK_NAME)
@Tag(Tags.OPENJCEPLUS_OPENSSL_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@Tag(Tags.MULTITHREAD_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getOpenJCEPlusWithSunJCEInteropProvider")
public class TestAESInterop extends BaseTestInterop {

    @Parameter(0)
    TestProvider provider;

    @Parameter(1)
    TestProvider interopProvider;

    static final byte[] plainText14 = "12345678123456".getBytes();
    static final byte[] plainText16 = "1234567812345678".getBytes();
    static final byte[] plainText18 = "123456781234567812".getBytes();
    static final byte[] plainText63 = "123456781234567812345678123456781234567812345678123456781234567"
            .getBytes();
    static final byte[] plainText128 = "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            .getBytes();

    Random r = new Random(5);
    static int iteration = 0;
    static final byte[] plainText512 = new byte[512];
    static final byte[] plainText65536 = new byte[65536];
    static final byte[] plainText524288 = new byte[524288];
    static final byte[] plainText1048576 = new byte[1048576];
    static final byte[] plainText16KB = new byte[16384];
    static final byte[] plainText = plainText128;

    protected SecretKey key;
    protected AlgorithmParameters params = null;
    protected Cipher cpA = null;
    protected Cipher cpB = null;

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
        setAndInsertInteropProvider(interopProvider);
        r.nextBytes(plainText512);
        r.nextBytes(plainText65536);
        r.nextBytes(plainText524288);
        r.nextBytes(plainText1048576);
        r.nextBytes(plainText16KB);
        setKeyForSize(128);
    }

    protected void setKeyForSize(int keySize) {
        byte[] keyBytes = new byte[keySize / 8];
        r.nextBytes(keyBytes);
        key = new SecretKeySpec(keyBytes, "AES");
    }

    @Test
    public void testAES() throws Exception {
        for (int ks : new int[]{128, 192, 256}) {
            setKeyForSize(ks);
            encryptDecrypt("AES", getProviderName(), getInteropProviderName());
            encryptDecrypt("AES", getInteropProviderName(), getProviderName());
        }
    }

    @Test
    public void testAES_CBC_NoPadding() throws Exception {
        for (int ks : new int[]{128, 192, 256}) {
            setKeyForSize(ks);
            encryptDecrypt("AES/CBC/NoPadding", true, false, getProviderName(), getInteropProviderName());
            encryptDecrypt("AES/CBC/NoPadding", true, false, getInteropProviderName(), getProviderName());
        }
    }

    @Test
    public void testAES_CBC_PKCS5Padding() throws Exception {
        for (int ks : new int[]{128, 192, 256}) {
            setKeyForSize(ks);
            encryptDecrypt("AES/CBC/PKCS5Padding", getProviderName(), getInteropProviderName());
            encryptDecrypt("AES/CBC/PKCS5Padding", getInteropProviderName(), getProviderName());
        }
    }

    @Test
    public void testAES_CFB8_NoPadding() throws Exception {
        for (int ks : new int[]{128, 192, 256}) {
            setKeyForSize(ks);
            encryptDecrypt("AES/CFB8/NoPadding", getProviderName(), getInteropProviderName());
            encryptDecrypt("AES/CFB8/NoPadding", getInteropProviderName(), getProviderName());
        }
    }

    @Test
    public void testAES_CFB_NoPadding() throws Exception {
        for (int ks : new int[]{128, 192, 256}) {
            setKeyForSize(ks);
            encryptDecrypt("AES/CFB/NoPadding", getProviderName(), getInteropProviderName());
            encryptDecrypt("AES/CFB/NoPadding", getInteropProviderName(), getProviderName());
        }
    }

    @Test
    public void testAES_CFB128_NoPadding() throws Exception {
        for (int ks : new int[]{128, 192, 256}) {
            setKeyForSize(ks);
            encryptDecrypt("AES/CFB128/NoPadding", getProviderName(), getInteropProviderName());
            encryptDecrypt("AES/CFB128/NoPadding", getInteropProviderName(), getProviderName());
        }
    }

    @Test
    public void testAES_CTR_NoPadding() throws Exception {
        for (int ks : new int[]{128, 192, 256}) {
            setKeyForSize(ks);
            encryptDecrypt("AES/CTR/NoPadding", getProviderName(), getInteropProviderName());
            encryptDecrypt("AES/CTR/NoPadding", getInteropProviderName(), getProviderName());
        }
    }

    @Test
    public void testAES_ECB_NoPadding() throws Exception {
        for (int ks : new int[]{128, 192, 256}) {
            setKeyForSize(ks);
            encryptDecrypt("AES/ECB/NoPadding", true, false, getProviderName(), getInteropProviderName());
            encryptDecrypt("AES/ECB/NoPadding", true, false, getInteropProviderName(), getProviderName());
        }
    }

    @Test
    public void testAES_ECB_PKCS5Padding() throws Exception {
        for (int ks : new int[]{128, 192, 256}) {
            setKeyForSize(ks);
            encryptDecrypt("AES/ECB/PKCS5Padding", getProviderName(), getInteropProviderName());
            encryptDecrypt("AES/ECB/PKCS5Padding", getInteropProviderName(), getProviderName());
        }
    }

    @Test
    public void testAES_OFB_NoPadding() throws Exception {
        for (int ks : new int[]{128, 192, 256}) {
            setKeyForSize(ks);
            encryptDecrypt("AES/OFB/NoPadding", getProviderName(), getInteropProviderName());
            encryptDecrypt("AES/OFB/NoPadding", getInteropProviderName(), getProviderName());
        }
    }

    @Test
    public void testAESShortBuffer() throws Exception {
        String msg = doTestAESShortBuffer("AES", getProviderName());
        String interopMsg = doTestAESShortBuffer("AES", getInteropProviderName());
        assertEquals(msg, interopMsg);
    }

    private String doTestAESShortBuffer(String algorithm, String providerA) throws Exception {
        String msg = null;
        try {
            cpA = Cipher.getInstance(algorithm, providerA);
            cpA.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = new byte[5];
            cpA.doFinal(plainText, 0, plainText.length, cipherText);
            fail("Expected ShortBufferException did not occur for provider: " + providerA);
        } catch (ShortBufferException ex) {
            msg = ex.getMessage();
        }
        return msg;
    }

    @Test
    public void testAESIllegalBlockSizeEncrypt() throws Exception {
        doTestAESIllegalBlockSizeEncrypt("AES/CBC/NoPadding", getProviderName());
        doTestAESIllegalBlockSizeEncrypt("AES/CBC/NoPadding", getInteropProviderName());
    }

    private void doTestAESIllegalBlockSizeEncrypt(String algorithm, String providerA)
            throws Exception {
        try {
            cpA = Cipher.getInstance(algorithm, providerA);
            int blockSize = cpA.getBlockSize();
            byte[] message = new byte[blockSize - 1];
            cpA.init(Cipher.ENCRYPT_MODE, key);
            cpA.doFinal(message);
            fail("Expected IllegalBlockSizeException did not occur");
        } catch (IllegalBlockSizeException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testAESIllegalBlockSizeDecrypt() throws Exception {
        doTestAESIllegalBlockSizeDecrypt("AES/CBC/PKCS5Padding", getProviderName());
        doTestAESIllegalBlockSizeDecrypt("AES/CBC/PKCS5Padding", getInteropProviderName());
    }

    private void doTestAESIllegalBlockSizeDecrypt(String algorithm, String providerA)
            throws Exception {
        try {
            cpA = Cipher.getInstance(algorithm, providerA);
            cpA.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = cpA.doFinal(plainText);
            params = cpA.getParameters();
            cpA.init(Cipher.DECRYPT_MODE, key, params);
            cpA.doFinal(cipherText, 0, cipherText.length - 1);
            fail("Expected IllegalBlockSizeException did not occur");
        } catch (IllegalBlockSizeException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testAESBadPaddingDecrypt() throws NoSuchAlgorithmException, NoSuchProviderException,
            NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        doTestAESBadPaddingDecrypt("AES/CBC/PKCS5Padding", getProviderName(), getInteropProviderName());
        doTestAESBadPaddingDecrypt("AES/CBC/PKCS5Padding", getInteropProviderName(), getProviderName());
    }

    private void doTestAESBadPaddingDecrypt(String algorithm, String providerA, String providerB)
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException {
        try {
            cpA = Cipher.getInstance(algorithm, providerA);
            cpA.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = cpA.doFinal(plainText);
            params = cpA.getParameters();
            cipherText[cipherText.length - 1]++;

            cpB = Cipher.getInstance(algorithm, providerB);
            cpB.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText = cpB.doFinal(cipherText, 0, cipherText.length);
            if (Arrays.equals(plainText, newPlainText)) {
                fail("Expected failure did not occur");
            } else {
                assertTrue(true);
            }
        } catch (BadPaddingException | IllegalBlockSizeException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testAESOnlyFinal() throws Exception {
        byte[] fullBlock = "0123456789ABCDEF".getBytes();
        byte[] incompleteBlock = "0123456789ABCDEF012".getBytes();
        byte[] multipleFullBlocks = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".getBytes();
        String[] algorithms = {"AES/CFB8/NoPadding", "AES/CBC/PKCS5Padding", "AES/CBC/NoPadding"};

        for (int ks : new int[]{128, 192, 256}) {
            setKeyForSize(ks);
            for (String algorithm : algorithms) {
                doTestAESOnlyFinal(algorithm, fullBlock, getProviderName(), getInteropProviderName());
                doTestAESOnlyFinal(algorithm, incompleteBlock, getProviderName(), getInteropProviderName());
                doTestAESOnlyFinal(algorithm, multipleFullBlocks, getProviderName(), getInteropProviderName());

                doTestAESOnlyFinal(algorithm, fullBlock, getInteropProviderName(), getProviderName());
                doTestAESOnlyFinal(algorithm, incompleteBlock, getInteropProviderName(), getProviderName());
                doTestAESOnlyFinal(algorithm, multipleFullBlocks, getInteropProviderName(), getProviderName());
            }
        }
    }

    private void doTestAESOnlyFinal(String algorithm, byte[] msg, String providerA,
            String providerB) throws NoSuchAlgorithmException, NoSuchProviderException,
            NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        int expectedEncryptedFinalLength;
        if (algorithm.contains("NoPadding")) {
            expectedEncryptedFinalLength = msg.length;
        } else {
            expectedEncryptedFinalLength = msg.length + (16 - (msg.length % 16));
        }

        try {
            cpA = Cipher.getInstance(algorithm, providerA);
            cpA.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = cpA.doFinal(msg);
            if (cipherText.length != expectedEncryptedFinalLength) {
                fail("Failure: algorithm " + algorithm + " encrypted text length = "
                        + cipherText.length + " Expected encryption length="
                        + expectedEncryptedFinalLength);
            }
            params = cpA.getParameters();

            cpB = Cipher.getInstance(algorithm, providerB);
            cpB.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText = cpB.doFinal(cipherText, 0, cipherText.length);
            assertTrue(Arrays.equals(msg, newPlainText),
                    "Failure: algorithm " + algorithm + " decrypted plaintext does not match original");
        } catch (IllegalBlockSizeException ex) {
            if (algorithm.contains("NoPadding") && (msg.length % 16 != 0)) {
                assertTrue(true);
            } else {
                fail("Unexpected IllegalBlockSizeException: " + ex);
            }
        } catch (BadPaddingException ex) {
            fail("Unexpected BadPaddingException: " + ex);
        }
    }

    @Test
    public void testAESWithUpdateForEncryptionButOnlyFinalForDecryption() throws Exception {
        byte[] fullBlock = "0123456789ABCDEF".getBytes();
        byte[] incompleteBlock = "0123456789ABCDEF012".getBytes();
        byte[] multipleFullBlocks = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".getBytes();
        String[] algorithms = {"AES/CFB8/NoPadding", "AES/CBC/PKCS5Padding", "AES/CBC/NoPadding"};

        for (int ks : new int[]{128, 192, 256}) {
            setKeyForSize(ks);
            for (String algorithm : algorithms) {
                doTestAESWithUpdateForEncryptionButOnlyFinalForDecryption(algorithm, fullBlock,
                        getProviderName(), getInteropProviderName());
                doTestAESWithUpdateForEncryptionButOnlyFinalForDecryption(algorithm, incompleteBlock,
                        getProviderName(), getInteropProviderName());
                doTestAESWithUpdateForEncryptionButOnlyFinalForDecryption(algorithm, multipleFullBlocks,
                        getProviderName(), getInteropProviderName());

                doTestAESWithUpdateForEncryptionButOnlyFinalForDecryption(algorithm, fullBlock,
                        getInteropProviderName(), getProviderName());
                doTestAESWithUpdateForEncryptionButOnlyFinalForDecryption(algorithm, incompleteBlock,
                        getInteropProviderName(), getProviderName());
                doTestAESWithUpdateForEncryptionButOnlyFinalForDecryption(algorithm, multipleFullBlocks,
                        getInteropProviderName(), getProviderName());
            }
        }
    }

    private void doTestAESWithUpdateForEncryptionButOnlyFinalForDecryption(String algorithm,
            byte[] msg, String providerA, String providerB)
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException {
        int expectedEncryptedFinalLength;
        if (algorithm.contains("NoPadding")) {
            expectedEncryptedFinalLength = msg.length;
        } else {
            expectedEncryptedFinalLength = msg.length + (16 - (msg.length % 16));
        }

        try {
            cpA = Cipher.getInstance(algorithm, providerA);
            cpA.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherTextFromUpdate = cpA.update(msg);
            byte[] cipherTextFromFinal = cpA.doFinal();

            params = cpA.getParameters();
            int updateLen = (cipherTextFromUpdate != null) ? cipherTextFromUpdate.length : 0;
            int finalLen = (cipherTextFromFinal != null) ? cipherTextFromFinal.length : 0;
            byte[] cipherText = new byte[updateLen + finalLen];
            if (updateLen > 0) {
                System.arraycopy(cipherTextFromUpdate, 0, cipherText, 0, updateLen);
            }
            if (finalLen > 0) {
                System.arraycopy(cipherTextFromFinal, 0, cipherText, updateLen, finalLen);
            }
            if (cipherText.length != expectedEncryptedFinalLength) {
                fail("Failure: algorithm " + algorithm + " encrypted text length = "
                        + cipherText.length + " Expected encryption length="
                        + expectedEncryptedFinalLength);
            }

            cpB = Cipher.getInstance(algorithm, providerB);
            cpB.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText = cpB.doFinal(cipherText, 0, cipherText.length);
            assertTrue(Arrays.equals(msg, newPlainText),
                    "Failure: algorithm " + algorithm + " decrypted plaintext does not match original");
        } catch (IllegalBlockSizeException ex) {
            if (algorithm.contains("NoPadding") && (msg.length % 16 != 0)) {
                assertTrue(true);
            } else {
                fail("Unexpected IllegalBlockSizeException: " + ex);
            }
        } catch (BadPaddingException ex) {
            fail("Unexpected BadPaddingException: " + ex);
        }
    }

    @Test
    public void testAESWithUpdateForEncryptionAndDecryption() throws Exception {
        byte[] fullBlock = "0123456789ABCDEF".getBytes();
        byte[] incompleteBlock = "0123456789ABCDEF012".getBytes();
        byte[] multipleFullBlocks = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".getBytes();
        String[] algorithms = {"AES/CFB8/NoPadding", "AES/CBC/PKCS5Padding", "AES/CBC/NoPadding"};

        for (int ks : new int[]{128, 192, 256}) {
            setKeyForSize(ks);
            for (String algorithm : algorithms) {
                doTestAESWithUpdateEncryptionAndDecryption(algorithm, fullBlock, getProviderName(),
                        getInteropProviderName());
                doTestAESWithUpdateEncryptionAndDecryption(algorithm, incompleteBlock, getProviderName(),
                        getInteropProviderName());
                doTestAESWithUpdateEncryptionAndDecryption(algorithm, multipleFullBlocks,
                        getProviderName(), getInteropProviderName());

                doTestAESWithUpdateEncryptionAndDecryption(algorithm, fullBlock, getInteropProviderName(),
                        getProviderName());
                doTestAESWithUpdateEncryptionAndDecryption(algorithm, incompleteBlock, getInteropProviderName(),
                        getProviderName());
                doTestAESWithUpdateEncryptionAndDecryption(algorithm, multipleFullBlocks,
                        getInteropProviderName(), getProviderName());
            }
        }
    }

    private void doTestAESWithUpdateEncryptionAndDecryption(String algorithm, byte[] msg,
            String providerA, String providerB)
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException {
        int expectedEncryptedFinalLength;
        if (algorithm.contains("NoPadding")) {
            expectedEncryptedFinalLength = msg.length;
        } else {
            expectedEncryptedFinalLength = msg.length + (16 - (msg.length % 16));
        }

        byte[] cipherText = new byte[expectedEncryptedFinalLength];
        try {
            cpA = Cipher.getInstance(algorithm, providerA);
            byte[] cipherFromDoFinal = null;
            int actualEncryptedLength = 0;

            cpA.init(Cipher.ENCRYPT_MODE, key);
            int firstChunk = Math.min(16, msg.length);
            byte[] cipherFrom1stUpdate = cpA.update(msg, 0, firstChunk);
            int firstUpdateLen = (cipherFrom1stUpdate != null) ? cipherFrom1stUpdate.length : 0;
            if (firstUpdateLen > 0) {
                System.arraycopy(cipherFrom1stUpdate, 0, cipherText, 0, firstUpdateLen);
            }

            if ((msg.length - 16) > 16) {
                byte[] cipherFrom2ndUpdate = cpA.update(msg, 16, 16);
                int secondUpdateLen = (cipherFrom2ndUpdate != null) ? cipherFrom2ndUpdate.length : 0;
                if (secondUpdateLen > 0) {
                    System.arraycopy(cipherFrom2ndUpdate, 0, cipherText, firstUpdateLen, secondUpdateLen);
                }
                cipherFromDoFinal = cpA.doFinal(msg, 32, msg.length - 32);
                int doFinalLen = (cipherFromDoFinal != null) ? cipherFromDoFinal.length : 0;
                if (doFinalLen > 0) {
                    System.arraycopy(cipherFromDoFinal, 0, cipherText, firstUpdateLen + secondUpdateLen, doFinalLen);
                }
                actualEncryptedLength = firstUpdateLen + secondUpdateLen + doFinalLen;
            } else {
                cipherFromDoFinal = cpA.doFinal(msg, firstChunk, msg.length - firstChunk);
                int doFinalLen = (cipherFromDoFinal != null) ? cipherFromDoFinal.length : 0;
                if (doFinalLen > 0) {
                    System.arraycopy(cipherFromDoFinal, 0, cipherText, firstUpdateLen, doFinalLen);
                }
                actualEncryptedLength = firstUpdateLen + doFinalLen;
            }

            if (expectedEncryptedFinalLength != actualEncryptedLength) {
                fail("Failure: algorithm " + algorithm + " encrypted text length = "
                        + actualEncryptedLength + " Expected encryption length="
                        + expectedEncryptedFinalLength);
            }

            params = cpA.getParameters();
            cpB = Cipher.getInstance(algorithm, providerB);
            cpB.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText = cpB.doFinal(cipherText, 0, actualEncryptedLength);
            assertTrue(Arrays.equals(msg, newPlainText),
                    "Failure: algorithm " + algorithm + " decrypted plaintext did not match original");
        } catch (IllegalBlockSizeException ex) {
            if (algorithm.contains("NoPadding") && (msg.length % 16 != 0)) {
                assertTrue(true);
            } else {
                fail("Unexpected IllegalBlockSizeException: " + ex);
            }
        } catch (BadPaddingException ex) {
            fail("Unexpected BadPaddingException: " + ex);
        }
    }

    protected void encryptDecrypt(String algorithm, String providerA, String providerB)
            throws Exception {
        encryptDecrypt(algorithm, false, false, providerA, providerB);
    }

    protected void encryptDecrypt(String algorithm, boolean requireLengthMultipleBlockSize,
            boolean testFinalizeOnly, String providerA, String providerB) throws Exception {
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, null, testFinalizeOnly, providerA,
                providerB);
    }

    protected void encryptDecrypt(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams, boolean testFinalizeOnly, String providerA,
            String providerB) throws Exception {
        Cipher cA = Cipher.getInstance(algorithm, providerA);
        Cipher cB = Cipher.getInstance(algorithm, providerB);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText14,
                testFinalizeOnly, cA, cB);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText16,
                testFinalizeOnly, cA, cB);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText18,
                testFinalizeOnly, cA, cB);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText63,
                testFinalizeOnly, cA, cB);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText128,
                testFinalizeOnly, cA, cB);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText512,
                testFinalizeOnly, cA, cB);
        for (iteration = 32; iteration <= 16384; iteration += 32) {
            byte[] slice = Arrays.copyOfRange(plainText16KB, 0, iteration);
            encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, slice,
                    testFinalizeOnly, cA, cB);
        }
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText65536,
                testFinalizeOnly, cA, cB);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText524288,
                testFinalizeOnly, cA, cB);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText1048576,
                testFinalizeOnly, cA, cB);
    }

    protected void encryptDecrypt(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams, byte[] message, boolean testFinalizeOnly,
            Cipher cA, Cipher cB) throws Exception {
        if (testFinalizeOnly) {
            encryptDecryptDoFinal(algorithm, requireLengthMultipleBlockSize, algParams, message,
                    cA, cB);
            encryptDecryptReuseObject(algorithm, requireLengthMultipleBlockSize, algParams, message,
                    cA, cB);
            encryptDecryptDoFinalCopySafe(algorithm, requireLengthMultipleBlockSize, algParams,
                    message, cA, cB);
        } else {
            encryptDecryptDoFinal(algorithm, requireLengthMultipleBlockSize, algParams, message,
                    cA, cB);
            encryptDecryptUpdate(algorithm, requireLengthMultipleBlockSize, algParams, message,
                    cA, cB);
            encryptDecryptPartialUpdate(algorithm, requireLengthMultipleBlockSize, algParams,
                    message, cA, cB);
            encryptDecryptReuseObject(algorithm, requireLengthMultipleBlockSize, algParams, message,
                    cA, cB);
            encryptDecryptDoFinalCopySafe(algorithm, requireLengthMultipleBlockSize, algParams,
                    message, cA, cB);
            encryptDecryptUpdateCopySafe(algorithm, requireLengthMultipleBlockSize, algParams,
                    message, cA, cB);
        }
    }

    protected void encryptDecryptDoFinal(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams, byte[] message, Cipher cA, Cipher cB)
            throws Exception {
        if (algParams == null) {
            cA.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cA.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cA.getBlockSize();
        try {
            byte[] cipherText = cA.doFinal(message);
            AlgorithmParameters ap = cA.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(((blockSize > 0) && (message.length % blockSize) == 0),
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length);
            }

            cB.init(Cipher.DECRYPT_MODE, key, ap);
            byte[] newPlainText = cB.doFinal(cipherText);

            boolean success = Arrays.equals(newPlainText, message);
            assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);

            cB.init(Cipher.DECRYPT_MODE, key, ap);
            byte[] newPlainText2 = cB.doFinal(cipherText, 0, cipherText.length);
            success = Arrays.equals(newPlainText2, message);
            assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);
        } catch (IllegalBlockSizeException e) {
            assertTrue((!requireLengthMultipleBlockSize || (message.length % blockSize) != 0),
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length);
        }
    }

    protected void encryptDecryptUpdate(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams, byte[] message, Cipher cA, Cipher cB)
            throws Exception {
        if (algParams == null) {
            cA.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cA.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cA.getBlockSize();
        try {
            byte[] cipherText1 = cA.update(message);
            byte[] cipherText2 = cA.doFinal();
            AlgorithmParameters ap = cA.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(((message.length % blockSize) == 0),
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length);
            }

            cB.init(Cipher.DECRYPT_MODE, key, ap);
            byte[] newPlainText1 = (cipherText1 == null) ? new byte[0] : cB.update(cipherText1);
            byte[] newPlainText2 = cB.doFinal(cipherText2);

            int l = (newPlainText1 == null) ? 0 : newPlainText1.length;
            int rLen = (newPlainText2 == null) ? 0 : newPlainText2.length;
            byte[] newPlainText = new byte[l + rLen];

            if (l != 0) {
                System.arraycopy(newPlainText1, 0, newPlainText, 0, l);
            }
            if (rLen != 0) {
                System.arraycopy(newPlainText2, 0, newPlainText, l, rLen);
            }

            boolean success = Arrays.equals(newPlainText, message);
            assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);
        } catch (IllegalBlockSizeException e) {
            assertTrue((!requireLengthMultipleBlockSize || (message.length % blockSize) != 0),
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length);
        }
    }

    protected void encryptDecryptPartialUpdate(String algorithm,
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message,
            Cipher cA, Cipher cB) throws Exception {
        if (algParams == null) {
            cA.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cA.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cA.getBlockSize();
        int partialLen = message.length > 10 ? 10 : 1;
        try {
            byte[] cipherText1 = cA.update(message, 0, partialLen);
            byte[] cipherText2 = cA.doFinal(message, partialLen, message.length - partialLen);
            AlgorithmParameters ap = cA.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(((message.length % blockSize) == 0),
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length);
            }

            cB.init(Cipher.DECRYPT_MODE, key, ap);
            byte[] newPlainText1 = (cipherText1 == null) ? new byte[0] : cB.update(cipherText1);
            byte[] newPlainText2 = cB.doFinal(cipherText2);

            int l = (newPlainText1 == null) ? 0 : newPlainText1.length;
            int rLen = (newPlainText2 == null) ? 0 : newPlainText2.length;
            byte[] newPlainText = new byte[l + rLen];

            if (l != 0) {
                System.arraycopy(newPlainText1, 0, newPlainText, 0, l);
            }
            if (rLen != 0) {
                System.arraycopy(newPlainText2, 0, newPlainText, l, rLen);
            }

            boolean success = Arrays.equals(newPlainText, message);
            assertTrue(success, "Decrypted text does not match expected, partial msglen=" + message.length);
        } catch (IllegalBlockSizeException e) {
            assertTrue((!requireLengthMultipleBlockSize || (message.length % blockSize) != 0),
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length);
        }
    }

    protected void encryptDecryptReuseObject(String algorithm,
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message,
            Cipher cA, Cipher cB) throws Exception {
        if (algParams == null) {
            cA.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cA.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cA.getBlockSize();
        try {
            byte[] cipherText = cA.doFinal(message);
            AlgorithmParameters ap = cA.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(((blockSize > 0) && (message.length % blockSize) == 0),
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length);
            }

            byte[] cipherText2 = cA.doFinal(message);
            boolean success = Arrays.equals(cipherText2, cipherText);
            assertTrue(success, "Re-encrypted text does not match");

            cB.init(Cipher.DECRYPT_MODE, key, ap);
            byte[] newPlainText = cB.doFinal(cipherText);
            success = Arrays.equals(newPlainText, message);
            assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);

            byte[] newPlainText2 = cB.doFinal(cipherText, 0, cipherText.length);
            success = Arrays.equals(newPlainText2, newPlainText);
            assertTrue(success, "Re-decrypted text does not match");
        } catch (IllegalBlockSizeException e) {
            assertTrue((!requireLengthMultipleBlockSize || (message.length % blockSize) != 0),
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length);
        }
    }

    protected void encryptDecryptDoFinalCopySafe(String algorithm,
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message,
            Cipher cA, Cipher cB) throws Exception {
        if (algParams == null) {
            cA.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cA.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cA.getBlockSize();
        try {
            byte[] cipherText0 = cA.doFinal(message);

            byte[] resultBuffer = Arrays.copyOf(message, cA.getOutputSize(message.length));
            int resultLen = cA.doFinal(resultBuffer, 0, message.length, resultBuffer);
            byte[] cipherText = Arrays.copyOf(resultBuffer, resultLen);
            AlgorithmParameters ap = cA.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(((blockSize > 0) && (message.length % blockSize) == 0),
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length);
            }

            boolean success = Arrays.equals(cipherText, cipherText0);
            assertTrue(success, "Encrypted text does not match expected result");

            cB.init(Cipher.DECRYPT_MODE, key, ap);
            resultBuffer = Arrays.copyOf(cipherText, cipherText.length);
            resultLen = cB.doFinal(resultBuffer, 0, cipherText.length, resultBuffer);
            byte[] newPlainText = Arrays.copyOf(resultBuffer, resultLen);

            success = Arrays.equals(newPlainText, message);
            assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);
        } catch (IllegalBlockSizeException e) {
            assertTrue((!requireLengthMultipleBlockSize || (message.length % blockSize) != 0),
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length);
        }
    }

    protected void encryptDecryptUpdateCopySafe(String algorithm,
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message,
            Cipher cA, Cipher cB) throws Exception {
        if (algParams == null) {
            cA.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cA.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cA.getBlockSize();
        try {
            byte[] cipherText0 = cA.doFinal(message);

            byte[] resultBuffer = Arrays.copyOf(message, cA.getOutputSize(message.length));
            int cipherText1Len = cA.update(resultBuffer, 0, message.length, resultBuffer);
            byte[] cipherText2 = cA.doFinal();

            int finalLen = (cipherText2 != null) ? cipherText2.length : 0;
            byte[] cipherText = new byte[cipherText1Len + finalLen];
            System.arraycopy(resultBuffer, 0, cipherText, 0, cipherText1Len);
            if (finalLen > 0) {
                System.arraycopy(cipherText2, 0, cipherText, cipherText1Len, finalLen);
            }
            AlgorithmParameters ap = cA.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(((blockSize > 0) && (message.length % blockSize) == 0),
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length);
            }

            boolean success = Arrays.equals(cipherText, cipherText0);
            assertTrue(success, "Encrypted text does not match expected result");

            cB.init(Cipher.DECRYPT_MODE, key, ap);
            resultBuffer = Arrays.copyOf(cipherText, cB.getOutputSize(cipherText.length));
            int plainText1Len = cB.update(resultBuffer, 0, cipherText.length, resultBuffer);
            byte[] plainText2 = cB.doFinal();

            int p2Len = (plainText2 != null) ? plainText2.length : 0;
            byte[] newPlainText = new byte[plainText1Len + p2Len];
            System.arraycopy(resultBuffer, 0, newPlainText, 0, plainText1Len);
            if (p2Len > 0) {
                System.arraycopy(plainText2, 0, newPlainText, plainText1Len, p2Len);
            }

            success = Arrays.equals(newPlainText, message);
            assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);
        } catch (IllegalBlockSizeException e) {
            assertTrue((!requireLengthMultipleBlockSize || (message.length % blockSize) != 0),
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length);
        }
    }

    @Test
    public void testUpdateForAES_CBC_PKCS5Padding() throws Exception {
        try {
            byte[] iv = new byte[16];
            Arrays.fill(iv, (byte) 0);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            byte[] k = new byte[16];
            Arrays.fill(k, (byte) 1);
            SecretKeySpec secretKeySpec = new SecretKeySpec(k, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", getProviderName());
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] plain = new byte[10000];
            Arrays.fill(plain, (byte) 1);

            ByteBuffer buffer = ByteBuffer.allocate(cipher.getOutputSize(plain.length));
            clearUpdateForAES_CBC_PKCS5Padding(buffer);
            addDataUpdateForAES_CBC_PKCS5Padding(buffer, plain, plain.length);
            encodeDataForAES_CBC_PKCS5Padding(buffer, cipher);
            assertTrue(true);
        } catch (Exception ex) {
            fail("Unexpected exception: " + ex);
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
