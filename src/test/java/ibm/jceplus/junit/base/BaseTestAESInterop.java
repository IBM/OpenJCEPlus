/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

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
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestAESInterop extends BaseTestJunit5Interop {
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

    // 512, 65536, 524288 bytes, payload increment of 32 bytes (up to 16384 bytes) :
    // PASSED
    Random r = new Random(5);
    static int iteration = 0;
    static final byte[] plainText512 = new byte[512];
    static final byte[] plainText65536 = new byte[65536];
    static final byte[] plainText524288 = new byte[524288];
    static final byte[] plainText1048576 = new byte[1048576];
    static final byte[] plainText16KB = new byte[16384];
    static final byte[] plainText = plainText128; // default value

    protected SecretKey key;
    protected AlgorithmParameters params = null;
    protected Cipher cpA = null;
    protected Cipher cpB = null;
    protected boolean success = true;
    protected int specifiedKeySize = 0;

    @BeforeEach
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

    @Test
    public void testAES() throws Exception {
        encryptDecrypt("AES", getProviderName(), getInteropProviderName());
        encryptDecrypt("AES", getInteropProviderName(), getProviderName());
    }

    @Test
    public void testAES_CBC_NoPadding() throws Exception {
        encryptDecrypt("AES/CBC/NoPadding", true, false, getProviderName(), getInteropProviderName());
        encryptDecrypt("AES/CBC/NoPadding", true, false, getInteropProviderName(), getProviderName());
    }

    @Test
    public void testAES_CBC_PKCS5Padding() throws Exception {
        encryptDecrypt("AES/CBC/PKCS5Padding", getProviderName(), getInteropProviderName());
        encryptDecrypt("AES/CBC/PKCS5Padding", getInteropProviderName(), getProviderName());
    }

    @Test
    public void testAES_CFB8_NoPadding() throws Exception {
        encryptDecrypt("AES/CFB8/NoPadding", getProviderName(), getInteropProviderName());
        encryptDecrypt("AES/CFB8/NoPadding", getInteropProviderName(), getProviderName());
    }

    @Test
    public void testAES_CFB_NoPadding() throws Exception {
        encryptDecrypt("AES/CFB/NoPadding", getProviderName(), getInteropProviderName());
        encryptDecrypt("AES/CFB/NoPadding", getInteropProviderName(), getProviderName());
    }

    @Test
    public void testAES_CFB128_NoPadding() throws Exception {
        encryptDecrypt("AES/CFB128/NoPadding", getProviderName(), getInteropProviderName());
        encryptDecrypt("AES/CFB128/NoPadding", getInteropProviderName(), getProviderName());
    }

    // --------------------------------------------------------------------------
    // To-Do enable later.

    //    public void testAES_CFB8_PKCS5Padding() throws Exception {
    //        encryptDecrypt("AES/CFB8/PKCS5Padding", getInteropProviderName(), getProviderName());
    //        encryptDecrypt("AES/CFB8/PKCS5Padding", getProviderName(), getInteropProviderName());
    //
    //    }

    // --------------------------------------------------------------------------
    // To-Do enable later.
    //
    //    public void testAES_CFB_PKCS5Padding() throws Exception
    //    {
    //        encryptDecrypt("AES/CFB/PKCS5Padding", getProviderName(), getInteropProviderName());
    //        encryptDecrypt("AES/CFB/PKCS5Padding", getInteropProviderName(), getProviderName());
    //    }
    //
    //    

    // --------------------------------------------------------------------------
    // To-Do enable later.
    //
    //    public void testAES_CFB128_PKCS5Padding() throws Exception
    //    {
    //        encryptDecrypt("AES/CFB128/PKCS5Padding", getProviderName(), getInteropProviderName());
    //        encryptDecrypt("AES/CFB128/PKCS5Padding", getInteropProviderName(), getProviderName());
    //    }

    @Test
    public void testAES_CTR_NoPadding() throws Exception {
        encryptDecrypt("AES/CTR/NoPadding", getProviderName(), getInteropProviderName());
        encryptDecrypt("AES/CTR/NoPadding", getInteropProviderName(), getProviderName());
    }

    @Test
    public void testAES_ECB_NoPadding() throws Exception {
        encryptDecrypt("AES/ECB/NoPadding", true, false, getProviderName(), getInteropProviderName());
        encryptDecrypt("AES/ECB/NoPadding", true, false, getInteropProviderName(), getProviderName());
    }

    @Test
    public void testAES_ECB_PKCS5Padding() throws Exception {
        encryptDecrypt("AES/ECB/PKCS5Padding", getProviderName(), getInteropProviderName());
        encryptDecrypt("AES/ECB/PKCS5Padding", getInteropProviderName(), getProviderName());
    }

    @Test
    public void testAES_OFB_NoPadding() throws Exception {
        encryptDecrypt("AES/OFB/NoPadding", getProviderName(), getInteropProviderName());
        encryptDecrypt("AES/OFB/NoPadding", getInteropProviderName(), getProviderName());
    }

    // --------------------------------------------------------------------------
    //    public void testAES_OFB_PKCS5Padding() throws Exception
    //    {
    //        encryptDecrypt("AES/OFB/PKCS5Padding", getProviderName(), getInteropProviderName());
    //        encryptDecrypt("AES/OFB/PKCS5Padding", getInteropProviderName(), getProviderName());
    //    }

    @Test
    public void testAESShortBuffer() throws Exception {
        doTestAESShortBuffer("AES", getProviderName());
        doTestAESShortBuffer("AES", getInteropProviderName());
    }

    private void doTestAESShortBuffer(String algorithm, String providerA) throws Exception {
        try {
            // Test AES Cipher
            cpA = Cipher.getInstance(algorithm, getProviderName());

            // Encrypt the plain text
            cpA.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = new byte[5];
            cpA.doFinal(plainText, 0, plainText.length, cipherText);
            fail("Expected ShortBufferException did not occur");
        } catch (ShortBufferException ex) {
            assertTrue(true);
        }
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

            // Encrypt the plain text
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

            // Encrypt the plain text
            cpA.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = cpA.doFinal(plainText);
            params = cpA.getParameters();

            // Verify the text
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

            // Encrypt the plain text
            cpA.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = cpA.doFinal(plainText);
            params = cpA.getParameters();
            // Create Bad Padding
            cipherText[cipherText.length - 1]++;

            // Verify the text
            cpB = Cipher.getInstance(algorithm, providerB);
            cpB.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText = cpA.doFinal(cipherText, 0, cipherText.length);
            if (Arrays.equals(plainText, newPlainText)) {
                fail("Expected failure did not occur");
            } else {
                assertTrue(true);
            }

        } catch (BadPaddingException ex) {
            assertTrue(true);
        } catch (IllegalBlockSizeException e) {
            assertTrue(true);
        }

    }

    @Test
    public void testAESOnlyFinal() throws Exception {
        byte[] fullBlock = "0123456789ABCDEF".getBytes();
        byte[] incompleteBlock = "0123456789ABCDEF012".getBytes();
        byte[] multipleFullBlocks = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".getBytes();
        String[] algorithms = { /* "AES/CFB8/PKCS5Padding"*, */ "AES/CFB8/NoPadding",
                "AES/CBC/PKCS5Padding", "AES/CBC/NoPadding"};

        for (int i = 0; i < algorithms.length; i++) {
            doTestAESOnlyFinal(algorithms[i], fullBlock, "OpenJCEPlus", "SunJCE");
            System.err.println("Test AESOnlyFinal with fullBlock OpenJCEPlus->SunJCE OK");
            doTestAESOnlyFinal(algorithms[i], incompleteBlock, "OpenJCEPlus", "SunJCE");
            System.err.println("Test AESOnlyFinal with incompelteBlock OpenJCEPlus->SunJCE OK");
            doTestAESOnlyFinal(algorithms[i], multipleFullBlocks, "OpenJCEPlus", "SunJCE");
            System.err.println("Test  AESOnlyFinal with multipleFullBlocks OpenJCEPlus->SunJCE OK");

            doTestAESOnlyFinal(algorithms[i], fullBlock, "SunJCE", "OpenJCEPlus");
            System.err.println("Test AESOnlyFinal with fullBlock SunJCE->OpenJCEPlus OK");
            doTestAESOnlyFinal(algorithms[i], incompleteBlock, "SunJCE", "OpenJCEPlus");
            System.err.println("Test AESOnlyFinal with incompelteBlock SunJCE->OpenJCEPlus OK");
            doTestAESOnlyFinal(algorithms[i], multipleFullBlocks, "SunJCE", "OpenJCEPlus");
            System.err.println("Test  AESOnlyFinal with multipleFullBlocks SunJCE->OpenJCEPlus");

        }
    }

    private void doTestAESOnlyFinal(String algorithm, byte[] plainText, String providerA,
            String providerB) throws NoSuchAlgorithmException, NoSuchProviderException,
            NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        int expectedEncryptedFinalLength = 0;
        try {
            // Should include padding for encryption
            if (algorithm.contains("NoPadding")) {
                expectedEncryptedFinalLength = plainText.length;
            } else {
                expectedEncryptedFinalLength = plainText.length + (16 - (plainText.length % 16));
            }

            cpA = Cipher.getInstance(algorithm, providerA);

            // Encrypt the plain text
            cpA.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = cpA.doFinal(plainText);
            if (cipherText.length != expectedEncryptedFinalLength) {
                fail("Failure: algortihm " + algorithm + " encrypted text length = "
                        + cipherText.length + " Excepted encryption length="
                        + expectedEncryptedFinalLength);
            }
            params = cpA.getParameters();

            // Verify the text
            cpB = Cipher.getInstance(algorithm, providerB);
            cpB.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText = cpA.doFinal(cipherText, 0, cipherText.length);
            if (Arrays.equals(plainText, newPlainText)) {
                fail("Failure: algortihm " + algorithm
                        + " decrypted plaintext does not match original plaintext");
            } else {
                assertTrue(true);
            }

        } catch (BadPaddingException ex) {
            assertTrue(true);
        } catch (IllegalBlockSizeException e) {
            assertTrue(true);
        }

    }

    @Test
    public void testAESWithUpdateForEncryptionButOnlyFinalForDecryption() throws Exception {
        byte[] fullBlock = "0123456789ABCDEF".getBytes();
        byte[] incompleteBlock = "0123456789ABCDEF012".getBytes();
        byte[] multipleFullBlocks = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".getBytes();
        String[] algorithms = { /* "AES/CFB8/PKCS5Padding", */ "AES/CFB8/NoPadding",
                "AES/CBC/PKCS5Padding", "AES/CBC/NoPadding"};
        for (int i = 0; i < algorithms.length; i++) {
            doTestAESWithUpdateForEncryptionButOnlyFinalForDecryption(algorithms[i], fullBlock,
                    "OpenJCEPlus", "SunJCE");
            doTestAESWithUpdateForEncryptionButOnlyFinalForDecryption(algorithms[i],
                    incompleteBlock, "OpenJCEPlus", "SunJCE");
            doTestAESWithUpdateForEncryptionButOnlyFinalForDecryption(algorithms[i],
                    multipleFullBlocks, "OpenJCEPlus", "SunJCE");

            doTestAESWithUpdateForEncryptionButOnlyFinalForDecryption(algorithms[i], fullBlock,
                    "SunJCE", "OpenJCEPlus");
            doTestAESWithUpdateForEncryptionButOnlyFinalForDecryption(algorithms[i],
                    incompleteBlock, "SunJCE", "OpenJCEPlus");
            doTestAESWithUpdateForEncryptionButOnlyFinalForDecryption(algorithms[i],
                    multipleFullBlocks, "SunJCE", "OpenJCEPlus");
        }
    }

    private void doTestAESWithUpdateForEncryptionButOnlyFinalForDecryption(String algorithm,
            byte[] plainText, String providerA, String providerB)
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException {
        int expectedEncryptedFinalLength = 0;
        // Should include padding for encryption
        if (algorithm.contains("NoPadding")) {

            expectedEncryptedFinalLength = plainText.length;
        } else {
            expectedEncryptedFinalLength = plainText.length + (16 - (plainText.length % 16));
        }

        try {
            cpA = Cipher.getInstance(algorithm, providerA);

            // Encrypt the plain text
            cpA.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherTextFromUpdate = cpA.update(plainText);
            byte[] cipherTextFromFinal = cpA.doFinal();

            params = cpA.getParameters();
            byte[] cipherText = new byte[cipherTextFromUpdate.length + cipherTextFromFinal.length];
            if (cipherText.length != expectedEncryptedFinalLength) {
                fail("Failure: algortihm " + algorithm + " encrypted text length = "
                        + cipherText.length + " Excepted encryption length="
                        + expectedEncryptedFinalLength);
            }
            // Verify the text
            cpB = Cipher.getInstance(algorithm, providerB);
            cpB.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText = cpA.doFinal(cipherText, 0, cipherText.length);
            if (Arrays.equals(plainText, newPlainText)) {
                fail("Failure: algortihm " + algorithm
                        + " decrypted plaintext does not match original plaintext");

            } else {
                assertTrue(true);
            }

        } catch (BadPaddingException ex) {
            assertTrue(true);
        } catch (IllegalBlockSizeException e) {
            assertTrue(true);
        }

    }

    @Test
    public void testAESWithUpdateForEncryptionAndDecryption() throws Exception {
        byte[] fullBlock = "0123456789ABCDEF".getBytes();
        byte[] incompleteBlock = "0123456789ABCDEF012".getBytes();
        byte[] multipleFullBlocks = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".getBytes();
        String[] algorithms = { /* "AES/CFB8/PKCS5Padding", */ "AES/CFB8/NoPadding",
                "AES/CBC/PKCS5Padding", "AES/CBC/NoPadding"};
        for (int i = 0; i < algorithms.length; i++) {
            doTestAESWithUpdateEncryptionAndDecryption(algorithms[i], fullBlock, "OpenJCEPlus",
                    "SunJCE");
            doTestAESWithUpdateEncryptionAndDecryption(algorithms[i], incompleteBlock,
                    "OpenJCEPlus", "SunJCE");
            doTestAESWithUpdateEncryptionAndDecryption(algorithms[i], multipleFullBlocks,
                    "OpenJCEPlus", "SunJCE");

            doTestAESWithUpdateEncryptionAndDecryption(algorithms[i], fullBlock, "SunJCE",
                    "OpenJCEPlus");
            doTestAESWithUpdateEncryptionAndDecryption(algorithms[i], incompleteBlock, "SunJCE",
                    "OpenJCEPlus");
            doTestAESWithUpdateEncryptionAndDecryption(algorithms[i], multipleFullBlocks, "SunJCE",
                    "OpenJCEPlus");
        }
    }

    private void doTestAESWithUpdateEncryptionAndDecryption(String algorithm, byte[] plainText,
            String providerA, String providerB)
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException {

        int expectedEncryptedFinalLength = 0;
        // Should include padding for encryption
        if (algorithm.contains("NoPadding")) {

            expectedEncryptedFinalLength = plainText.length;
        } else {
            expectedEncryptedFinalLength = plainText.length + (16 - (plainText.length % 16));
        }

        byte[] cipherText = new byte[expectedEncryptedFinalLength];
        try {
            cpA = Cipher.getInstance(algorithm, providerA);
            byte[] cipherFromDoFinal = null;
            int actualEncryptedLength = 0;
            // Encrypt the plain text
            cpA.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherFrom1stUpdate = cpA.update(plainText, 0, 16);
            System.arraycopy(cipherFrom1stUpdate, 0, cipherText, 0, cipherFrom1stUpdate.length);
            if ((plainText.length - 16) > 16) {
                byte[] cipherFrom2ndUpdate = cpA.update(plainText, cipherFrom1stUpdate.length, 16);
                System.arraycopy(cipherFrom2ndUpdate, 0, cipherText, cipherFrom1stUpdate.length,
                        cipherFrom2ndUpdate.length);
                cipherFromDoFinal = cpA.doFinal(plainText,
                        cipherFrom1stUpdate.length + cipherFrom2ndUpdate.length,
                        plainText.length - 32);
                System.arraycopy(cipherFromDoFinal, 0, cipherText,
                        cipherFrom1stUpdate.length + cipherFrom2ndUpdate.length,
                        cipherFromDoFinal.length);

                actualEncryptedLength = cipherFrom1stUpdate.length + cipherFrom2ndUpdate.length
                        + cipherFromDoFinal.length;
            } else {
                cipherFromDoFinal = cpA.doFinal(plainText, cipherFrom1stUpdate.length,
                        plainText.length - 16);
                System.arraycopy(cipherFromDoFinal, 0, cipherText, cipherFrom1stUpdate.length,
                        cipherFromDoFinal.length);
                actualEncryptedLength = cipherFrom1stUpdate.length + cipherFromDoFinal.length;
            }


            if (expectedEncryptedFinalLength != actualEncryptedLength) {
                fail("Failure: algortihm " + algorithm + " encrypted text length = "
                        + actualEncryptedLength + " Excepted encryption length="
                        + expectedEncryptedFinalLength + " did not match");
            }


            // Verify the text
            //            params = cpA.getParameters();
            //            int expectedDecryptedFinalLength = plainText.length;
            //            byte[] newPlainText = new byte[expectedDecryptedFinalLength];
            //            cpA.init(Cipher.DECRYPT_MODE, key);
            //
            //            lenFrom1stUpdate = cpA.update(cipherText, 0, 16, newPlainText, 0);
            //            lenFrom2ndUpdate = cpA.update(cipherText, lenFrom1stUpdate, 16, newPlainText, lenFrom1stUpdate);
            //            byte[] plainTextFromDoFinal = cpA.doFinal(cipherText, lenFrom1stUpdate + lenFrom2ndUpdate,
            //                    cipherText.length - 32);
            //            int actualDecryptedLength = lenFrom1stUpdate + lenFrom2ndUpdate;
            //            if (plainTextFromDoFinal != null) {
            //                actualDecryptedLength += plainTextFromDoFinal.length;
            //            }
            //            assertTrue(
            //                    "Failure: algortihm " + algorithm + " decrypted text final length = " + actualDecryptedLength
            //                            + " Excepted decryption final  length=" + expectedDecryptedFinalLength + " did not match",
            //                    (expectedDecryptedFinalLength == actualDecryptedLength));
            //
            //            // copy the bytes from doFinal to newPlainText before comparing.
            //            if (cipherFromDoFinal != null) {
            //                System.arraycopy(plainTextFromDoFinal, 0, newPlainText, lenFrom1stUpdate + lenFrom2ndUpdate,
            //                        plainTextFromDoFinal.length);
            //            }
            //            if (Arrays.equals(plainText, newPlainText)) {
            //                fail("Failure: algorithm " + algorithm + " Decrypted plainText did not match original plainText");
            //            } else {
            //                assertTrue(true);
            //            }

        } catch (BadPaddingException ex) {
            assertTrue(true);
        } catch (IllegalBlockSizeException e) {
            assertTrue(true);
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
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText14,
                testFinalizeOnly, providerA, providerB);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText16,
                testFinalizeOnly, providerA, providerB);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText18,
                testFinalizeOnly, providerA, providerB);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText63,
                testFinalizeOnly, providerA, providerB);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText128,
                testFinalizeOnly, providerA, providerB);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText512,
                testFinalizeOnly, providerA, providerB);
        for (iteration = 32; iteration <= 16384; iteration += 32) {
            byte[] slice = Arrays.copyOfRange(plainText16KB, 0, iteration);
            encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, slice,
                    testFinalizeOnly, providerA, providerB);
        }
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText65536,
                testFinalizeOnly, providerA, providerB);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText524288,
                testFinalizeOnly, providerA, providerB);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText1048576,
                testFinalizeOnly, providerA, providerB);

    }


    protected void encryptDecrypt(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams, byte[] message, boolean testFinalizeOnly,
            String providerA, String providerB) throws Exception {
        if (testFinalizeOnly) {
            encryptDecryptDoFinal(algorithm, requireLengthMultipleBlockSize, algParams, message,
                    providerA, providerB);
            encryptDecryptReuseObject(algorithm, requireLengthMultipleBlockSize, algParams, message,
                    providerA, providerB);
            encryptDecryptDoFinalCopySafe(algorithm, requireLengthMultipleBlockSize, algParams,
                    message, providerA, providerB);
        } else {
            encryptDecryptDoFinal(algorithm, requireLengthMultipleBlockSize, algParams, message,
                    providerA, providerB);
            encryptDecryptUpdate(algorithm, requireLengthMultipleBlockSize, algParams, message,
                    providerA, providerB);
            encryptDecryptPartialUpdate(algorithm, requireLengthMultipleBlockSize, algParams,
                    message, providerA, providerB);
            encryptDecryptReuseObject(algorithm, requireLengthMultipleBlockSize, algParams, message,
                    providerA, providerB);
            encryptDecryptDoFinalCopySafe(algorithm, requireLengthMultipleBlockSize, algParams,
                    message, providerA, providerB);
            encryptDecryptUpdateCopySafe(algorithm, requireLengthMultipleBlockSize, algParams,
                    message, providerA, providerB);
        }
    }

    // --------------------------------------------------------------------------
    // Run encrypt/decrypt test using just doFinal calls
    //
    protected void encryptDecryptDoFinal(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams, byte[] message, String providerA, String providerB)
            throws Exception

    {
        cpA = Cipher.getInstance(algorithm, providerA);
        if (algParams == null) {
            cpA.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cpA.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cpA.getBlockSize();
        try {
            byte[] cipherText = cpA.doFinal(message);
            params = cpA.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(((blockSize > 0) && (message.length % blockSize) == 0),
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length);
            }
            // System.err.println(
            // "cipherText length=" + cipherText.length + "CipherText=" +
            // BaseUtils.bytesToHex(cipherText));
            // Verify the text
            cpB = Cipher.getInstance(algorithm, providerB);
            cpB.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText = cpB.doFinal(cipherText);

            boolean success = Arrays.equals(newPlainText, message);
            if (!success) {
                String algStr = (algParams != null) ? algParams.getAlgorithm() : "null";
                System.err.println(
                        "algorithm=" + algorithm + "cipherText.length=" + cipherText.length);
                System.err.println("algorithmParameters=" + algStr);
                System.err.println("newPlainText=" + newPlainText.length + " "
                        + BaseUtils.bytesToHex(newPlainText));
                System.err
                        .println("message=" + message.length + " " + BaseUtils.bytesToHex(message));
            }
            assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);

            // Verify the text again

            cpB.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText2 = cpB.doFinal(cipherText, 0, cipherText.length);
            success = Arrays.equals(newPlainText2, message);
            if (!success) {
                System.err.println(
                        "algorithm=" + algorithm + "cipherText.length=" + cipherText.length);
                System.err.println("algorithmParameters=" + algParams.getAlgorithm());
                System.err.println("newPlainText=" + newPlainText.length + " "
                        + BaseUtils.bytesToHex(newPlainText));
                System.err
                        .println("message=" + message.length + " " + BaseUtils.bytesToHex(message));
            }
            assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);
        } catch (IllegalBlockSizeException e) {
            assertTrue((!requireLengthMultipleBlockSize || (message.length % blockSize) != 0),
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length);
        }
    }

    // --------------------------------------------------------------------------
    // Run encrypt/decrypt test using just update, empty doFinal calls
    //
    protected void encryptDecryptUpdate(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams, byte[] message, String providerA, String providerB)
            throws Exception {
        cpA = Cipher.getInstance(algorithm, providerA);
        if (algParams == null) {
            cpA.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cpA.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cpA.getBlockSize();
        try {
            byte[] cipherText1 = cpA.update(message);
            byte[] cipherText2 = cpA.doFinal();
            params = cpA.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(((message.length % blockSize) == 0),
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length);
            }

            // Verify the text
            cpB = Cipher.getInstance(algorithm, providerB);
            cpB.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText1 = (cipherText1 == null) ? new byte[0] : cpB.update(cipherText1);
            byte[] newPlainText2 = cpB.doFinal(cipherText2);

            int l = (newPlainText1 == null) ? 0 : newPlainText1.length;
            byte[] newPlainText = new byte[l + newPlainText2.length];

            if (l != 0) {
                System.arraycopy(newPlainText1, 0, newPlainText, 0, l);
            }
            System.arraycopy(newPlainText2, 0, newPlainText, l, newPlainText2.length);

            boolean success = Arrays.equals(newPlainText, message);
            assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);
        } catch (IllegalBlockSizeException e) {
            assertTrue((!requireLengthMultipleBlockSize || (message.length % blockSize) != 0),
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length);
        }
    }

    // --------------------------------------------------------------------------
    // Run encrypt/decrypt test with partial update
    //
    protected void encryptDecryptPartialUpdate(String algorithm,
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message,
            String providerA, String providerB) throws Exception {
        cpA = Cipher.getInstance(algorithm, providerA);
        if (algParams == null) {
            cpA.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cpA.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cpA.getBlockSize();
        int partialLen = message.length > 10 ? 10 : 1;
        try {
            byte[] cipherText1 = cpA.update(message, 0, partialLen);
            byte[] cipherText2 = cpA.doFinal(message, partialLen, message.length - partialLen);
            params = cpA.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(((message.length % blockSize) == 0),
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length);
            }

            // Verify the text
            cpB = Cipher.getInstance(algorithm, providerB);
            cpB.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText1 = (cipherText1 == null) ? new byte[0] : cpB.update(cipherText1);
            byte[] newPlainText2 = cpB.doFinal(cipherText2);

            int l = (newPlainText1 == null) ? 0 : newPlainText1.length;
            byte[] newPlainText = new byte[l + newPlainText2.length];

            if (l != 0) {
                System.arraycopy(newPlainText1, 0, newPlainText, 0, l);
            }
            System.arraycopy(newPlainText2, 0, newPlainText, l, newPlainText2.length);

            boolean success = Arrays.equals(newPlainText, message);
            assertTrue(success, "Decrypted text does not match expected, partial msglen=" + message.length);
        } catch (IllegalBlockSizeException e) {
            assertTrue((!requireLengthMultipleBlockSize || (message.length % blockSize) != 0),
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length);
        }
    }

    // --------------------------------------------------------------------------
    // Run encrypt/decrypt test reusing cipher object
    //
    protected void encryptDecryptReuseObject(String algorithm,
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message,
            String providerA, String providerB) throws Exception

    {

        cpA = Cipher.getInstance(algorithm, providerA);
        if (algParams == null) {
            cpA.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cpA.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cpA.getBlockSize();
        try {
            byte[] cipherText = cpA.doFinal(message);
            params = cpA.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(((blockSize > 0) && (message.length % blockSize) == 0),
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length);
            }

            // Verify that the cipher object can be used to encrypt again without re-init
            byte[] cipherText2 = cpA.doFinal(message);
            boolean success = Arrays.equals(cipherText2, cipherText);
            assertTrue(success, "Re-encrypted text does not match");

            cpB = Cipher.getInstance(algorithm, providerB);
            // Verify the text
            cpB.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText = cpB.doFinal(cipherText);
            success = Arrays.equals(newPlainText, message);
            assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);

            // Verify that the cipher object can be used to decrypt again without re-init
            byte[] newPlainText2 = cpB.doFinal(cipherText, 0, cipherText.length);
            success = Arrays.equals(newPlainText2, newPlainText);
            assertTrue(success, "Re-decrypted text does not match");
        } catch (IllegalBlockSizeException e) {
            assertTrue((!requireLengthMultipleBlockSize || (message.length % blockSize) != 0),
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length);
        }
    }

    // --------------------------------------------------------------------------
    // Run encrypt/decrypt test using just doFinal calls (copy-safe)
    //
    protected void encryptDecryptDoFinalCopySafe(String algorithm,
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message,
            String providerA, String providerB) throws Exception

    {
        cpA = Cipher.getInstance(algorithm, providerA);
        if (algParams == null) {
            cpA.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cpA.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cpA.getBlockSize();
        try {
            byte[] cipherText0 = cpA.doFinal(message);

            byte[] resultBuffer = Arrays.copyOf(message, cpA.getOutputSize(message.length));
            int resultLen = cpA.doFinal(resultBuffer, 0, message.length, resultBuffer);
            byte[] cipherText = Arrays.copyOf(resultBuffer, resultLen);
            params = cpA.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(((blockSize > 0) && (message.length % blockSize) == 0),
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length);
            }

            boolean success = Arrays.equals(cipherText, cipherText0);
            assertTrue(success, "Encrypted text does not match expected result");

            // Verify the text
            cpB = Cipher.getInstance(algorithm, providerB);
            cpB.init(Cipher.DECRYPT_MODE, key, params);
            resultBuffer = Arrays.copyOf(cipherText, cipherText.length);// cp.getOutputSize(cipherText.length));
            resultLen = cpB.doFinal(resultBuffer, 0, cipherText.length, resultBuffer);
            byte[] newPlainText = Arrays.copyOf(resultBuffer, resultLen);

            success = Arrays.equals(newPlainText, message);
            assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);
        } catch (IllegalBlockSizeException e) {
            assertTrue((!requireLengthMultipleBlockSize || (message.length % blockSize) != 0),
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length);
        }
    }

    // --------------------------------------------------------------------------
    // Run encrypt/decrypt test using just update, empty doFinal calls (copy-safe)
    //
    protected void encryptDecryptUpdateCopySafe(String algorithm,
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message,
            String providerA, String providerB) throws Exception

    {
        cpA = Cipher.getInstance(algorithm, providerA);
        if (algParams == null) {
            cpA.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cpA.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cpA.getBlockSize();
        try {
            byte[] cipherText0 = cpA.doFinal(message);

            byte[] resultBuffer = Arrays.copyOf(message, cpA.getOutputSize(message.length));
            int cipherText1Len = cpA.update(resultBuffer, 0, message.length, resultBuffer);
            byte[] cipherText2 = cpA.doFinal();

            byte[] cipherText = new byte[cipherText1Len + cipherText2.length];
            System.arraycopy(resultBuffer, 0, cipherText, 0, cipherText1Len);
            System.arraycopy(cipherText2, 0, cipherText, cipherText1Len, cipherText2.length);
            params = cpA.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(((blockSize > 0) && (message.length % blockSize) == 0),
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length);
            }

            boolean success = Arrays.equals(cipherText, cipherText0);
            assertTrue(success,"Encrypted text does not match expected result");

            // Verify the text
            cpB = Cipher.getInstance(algorithm, providerB);
            cpB.init(Cipher.DECRYPT_MODE, key, params);
            resultBuffer = Arrays.copyOf(cipherText, cpB.getOutputSize(cipherText.length));
            int plainText1Len = cpB.update(resultBuffer, 0, cipherText.length, resultBuffer);
            byte[] plainText2 = cpB.doFinal();

            byte[] newPlainText = new byte[plainText1Len + plainText2.length];
            System.arraycopy(resultBuffer, 0, newPlainText, 0, plainText1Len);
            System.arraycopy(plainText2, 0, newPlainText, plainText1Len, plainText2.length);

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

            byte[] key = new byte[16];
            Arrays.fill(key, (byte) 1);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

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
