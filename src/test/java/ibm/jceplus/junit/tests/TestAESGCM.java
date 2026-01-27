/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@Tag(Tags.OPENJCEPLUS_MULTITHREAD_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_MULTITHREAD_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#aesKeySizesAndJCEPlusProviders")
public class TestAESGCM extends BaseTest {

    @Parameter(0)
    int keysize;

    @Parameter(1)
    TestProvider provider;

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
    // 4096 bytes: PASSED   Need to use this to test FastJNI cache size.
    static final String plainText4096String = "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            + "123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781";

    static final byte[] plainText4096 = plainText4096String.getBytes();
    static final byte[] plainText = plainText4096; // default value

    protected KeyGenerator aesKeyGen;
    protected SecretKey key;
    protected AlgorithmParameters params = null;
    protected boolean success = true;
    protected Method methodCipherUpdateAAD = null;
    protected Constructor<?> ctorGCMParameterSpec = null;
    protected Method methodGCMParameterSpecSetAAD = null;
    byte[] ivBytes = "123456".getBytes();
    byte[] aadBytes = new byte[16];

    @BeforeEach
    public void setUp() throws Exception {

        setKeySize(keysize);
        setAndInsertProvider(provider);

        aesKeyGen = KeyGenerator.getInstance("AES", getProviderName());
        int keySize = -1;
        try {
            keySize = getKeySize();
        } catch (RuntimeException e) {
            // Ignore exception since keysize was not set.
            // This is OK since we intend to test the default keysize.
        }
        if (keySize > 0) {
            aesKeyGen.init(keySize);
        }
        key = aesKeyGen.generateKey();

        try {
            Class<?> classCipher = Class.forName("javax.crypto.Cipher");
            methodCipherUpdateAAD = classCipher.getMethod("updateAAD", new Class<?>[] {byte[].class});
        } catch (Exception e) {
        }

        /*
         * Try constructing a javax.crypto.spec.GCMParameterSpec instance (Java
         * 7+)
         */
        try {
            Class<?> classGCMParameterSpec = Class.forName("javax.crypto.spec.GCMParameterSpec");
            ctorGCMParameterSpec = classGCMParameterSpec
                    .getConstructor(new Class<?>[] {int.class, byte[].class});
        } catch (Exception ex) {
            /* Differ to calling code in test cases that follow... */
        }

        /*
         * Try constructing an ibm.security.internal.spec.GCMParameterSpec
         * instance (IBM Java 6)
         */
        if (ctorGCMParameterSpec == null) {
            try {
                Class<?> classGCMParameterSpec = Class
                        .forName("ibm.security.internal.spec.GCMParameterSpec");
                ctorGCMParameterSpec = classGCMParameterSpec
                        .getConstructor(new Class<?>[] {int.class, byte[].class});
                methodGCMParameterSpecSetAAD = classGCMParameterSpec.getMethod("setAAD",
                        new Class<?>[] {byte[].class, int.class, int.class});
            } catch (Exception ex) {
                /* Differ to calling code in test cases that follow... */
            }
        }

        if (ctorGCMParameterSpec == null) {
            throw new Exception("Could not find GCMParameterSpec constructor");
        }
    }

    @Test
    public void testAES_GCM_encrypt_offset() throws Exception {
        // Test AES GCM - Encrypt Offset by 1
        Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

        byte[] iv = new byte[16];
        byte[] aad = new byte[16];

        // GCMParameterSpec gps = new GCMParameterSpec(16 * 8, iv);
        AlgorithmParameterSpec gps = (AlgorithmParameterSpec) ctorGCMParameterSpec
                .newInstance(16 * 8, iv);
        if (methodGCMParameterSpecSetAAD != null) {
            methodGCMParameterSpecSetAAD.invoke(gps, aad, 0, aad.length);
        }
        cp.init(Cipher.ENCRYPT_MODE, key, gps);
        // cp.updateAAD(aad, 0, aad.length);
        if (methodCipherUpdateAAD != null) {
            methodCipherUpdateAAD.invoke(cp, aad);
        }

        int offset = 1;
        byte[] encrypted = new byte[cp.getOutputSize(plainText.length) + offset];
        int encryptLength = cp.doFinal(plainText, 0, plainText.length, encrypted, offset);

        cp.init(Cipher.DECRYPT_MODE, key, gps);
        // cp.updateAAD(aad, 0, aad.length);
        if (methodCipherUpdateAAD != null) {
            methodCipherUpdateAAD.invoke(cp, aad);
        }

        byte[] decrypted = new byte[cp.getOutputSize(encryptLength)];
        cp.doFinal(encrypted, offset, encryptLength, decrypted, 0);

        assertTrue(byteEqual(plainText, 0, decrypted, 0, plainText.length),
              "Decrypted text does not match expected");
    }

    @Test
    public void testAES_GCM_decrypt_offset() throws Exception {
        // Test AES GCM - Decrypt Offset by 1
        Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

        byte[] iv = new byte[16];
        byte[] aad = new byte[16];
        // GCMParameterSpec gps = new GCMParameterSpec(16 * 8, iv);
        AlgorithmParameterSpec gps = (AlgorithmParameterSpec) ctorGCMParameterSpec
                .newInstance(16 * 8, iv);
        if (methodGCMParameterSpecSetAAD != null) {
            methodGCMParameterSpecSetAAD.invoke(gps, aad, 0, aad.length);
        }
        cp.init(Cipher.ENCRYPT_MODE, key, gps);
        // cp.updateAAD(aad, 0, aad.length);
        if (methodCipherUpdateAAD != null) {
            methodCipherUpdateAAD.invoke(cp, aad);
        }

        byte[] encrypted = new byte[cp.getOutputSize(plainText.length)];
        int encryptLength = cp.doFinal(plainText, 0, plainText.length, encrypted, 0);

        cp.init(Cipher.DECRYPT_MODE, key, gps);
        // cp.updateAAD(aad, 0, aad.length);
        if (methodCipherUpdateAAD != null) {
            methodCipherUpdateAAD.invoke(cp, aad);
        }

        int offset = 1;
        byte[] decrypted = new byte[cp.getOutputSize(encryptLength) + offset];
        cp.doFinal(encrypted, 0, encryptLength, decrypted, offset);

        assertTrue(byteEqual(plainText, 0, decrypted, offset, plainText.length),
            "Decrypted text does not match expected");
    }

    @Test
    public void testAES_GCM_encrypt_large_buffer() throws Exception {
        // Test AES GCM - Encrypting buffer large
        Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

        byte[] iv = new byte[16];
        byte[] aad = new byte[16];
        // GCMParameterSpec gps = new GCMParameterSpec(16 * 8, iv);
        AlgorithmParameterSpec gps = (AlgorithmParameterSpec) ctorGCMParameterSpec
                .newInstance(16 * 8, iv);
        cp.init(Cipher.ENCRYPT_MODE, key, gps);
        // cp.updateAAD(aad, 0, aad.length);
        if (methodCipherUpdateAAD != null) {
            methodCipherUpdateAAD.invoke(cp, aad);
        }

        byte[] encrypted = new byte[5000];
        int expected_encryptLength = cp.getOutputSize(plainText.length);
        int encryptLength = cp.doFinal(plainText, 0, plainText.length, encrypted, 0);

        if (expected_encryptLength != encryptLength) {
            assertTrue(false, "Failure -\n" + "Actual   encrypt output length from Cipher.doFinal: "
                    + encryptLength + "\n" + "Expected encrypt output length from Cipher.doFinal: "
                    + expected_encryptLength + "\n"
                    + "Buffer encrypt length passed to Cipher.doFinal:     " + encrypted.length
                    + "\n");
        } else {
            assertTrue(true, "Passed - Output encrypt with large buffer");
        }
    }

    @Test
    public void testAES_GCM_decrypt_large_buffer() throws Exception {
        // Test AES GCM - Decrypting buffer large
        Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

        byte[] iv = new byte[16];
        byte[] aad = new byte[16];
        // GCMParameterSpec gps = new GCMParameterSpec(16 * 8, iv);
        AlgorithmParameterSpec gps = (AlgorithmParameterSpec) ctorGCMParameterSpec
                .newInstance(16 * 8, iv);
        cp.init(Cipher.ENCRYPT_MODE, key, gps);
        // cp.updateAAD(aad, 0, aad.length);
        if (methodCipherUpdateAAD != null) {
            methodCipherUpdateAAD.invoke(cp, aad);
        }

        byte[] encrypted = new byte[cp.getOutputSize(plainText.length)];
        int encryptLength = cp.doFinal(plainText, 0, plainText.length, encrypted, 0);

        cp.init(Cipher.DECRYPT_MODE, key, gps);
        // cp.updateAAD(aad, 0, aad.length);
        if (methodCipherUpdateAAD != null) {
            methodCipherUpdateAAD.invoke(cp, aad);
        }

        byte[] decrypted = new byte[5000];
        int expected_decryptLength = cp.getOutputSize(encrypted.length);
        int decryptLength = cp.doFinal(encrypted, 0, encryptLength, decrypted, 0);

        if (expected_decryptLength != decryptLength) {
            assertTrue(false, "Failure -\n" + "Actual   decrypt output length from Cipher.doFinal: "
                    + decryptLength + "\n" + "Expected decrypt output length from Cipher.doFinal: "
                    + expected_decryptLength + "\n"
                    + "Buffer decrypt length passed to Cipher.doFinal:     " + decrypted.length
                    + "\n");
        } else {
            assertTrue(true, "Passed - Output encrypt with large buffer");
        }
    }

    @Test
    public void testAES_GCM() throws Exception {
        // Test AES GCM Cipher
        Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

        // Encrypt the plain text
        cp.init(Cipher.ENCRYPT_MODE, key);
        params = cp.getParameters();
        byte[] cipherText1 = cp.doFinal(plainText);

        // Verify the text
        cp.init(Cipher.DECRYPT_MODE, key, params);
        byte[] newPlainText1 = cp.doFinal(cipherText1);

        assertTrue(byteEqual(plainText, 0, newPlainText1, 0, plainText.length),
            "Decrypted text does not match expected");
    }

    @Test
    public void testAES_GCM_2() throws Exception {
        // Test AES GCM Cipher using duplicate calls
        Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

        // Encrypt the plain text
        cp.init(Cipher.ENCRYPT_MODE, key);
        cp.init(Cipher.ENCRYPT_MODE, key); // do a second init
        params = cp.getParameters();
        byte[] cipherText1 = cp.doFinal(plainText);

        cp.init(Cipher.ENCRYPT_MODE, key); // call init again
        params = cp.getParameters();
        cipherText1 = cp.doFinal(plainText); // call final again

        // Verify the text
        cp.init(Cipher.DECRYPT_MODE, key, params);
        cp.init(Cipher.DECRYPT_MODE, key, params); // do a second init
        byte[] newPlainText1 = cp.doFinal(cipherText1);

        cp.init(Cipher.DECRYPT_MODE, key, params); // call init again
        newPlainText1 = cp.doFinal(cipherText1); // call final again

        assertTrue(byteEqual(plainText, 0, newPlainText1, 0, plainText.length),
            "Decrypted text does not match expected");
    }

    @Test
    public void testAES_GCM_encrypt_empty_text() throws Exception {
        try {
            // Test AES GCM - Encrypt Cipher.doFinal() without text
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

            // Encrypt the plain text
            cp.init(Cipher.ENCRYPT_MODE, key);
            params = cp.getParameters();
            cp.doFinal();
        } catch (Exception ex) {
            assertTrue(false, "Failed - Should not have been exception: \n" + ex.getStackTrace());
            return;
        }

        assertTrue(true, "Passed - Cipher.doFinal() encrypt empty text");
    }

    @Test
    public void testAES_GCM_decrypt_without_parameters() throws Exception {
        try {
            // Test AES GCM - Decrypt Cipher.doFinal() without parameters
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

            cp.init(Cipher.DECRYPT_MODE, key);
            cp.doFinal();
        } catch (Exception ex) {
            assertTrue(true,
                    "Passed - Cipher.doFinal() decrypt without parameters throws expected exception");
            return;
        }
        assertTrue(false,
                "Failed - Cipher.doFinal() decrypt without parameters should have thrown exception");
    }

    @Test
    public void testAES_GCM_decrypt_empty_text() throws Exception {
        try {
            // Test AES GCM - Decrypt Cipher.doFinal() without text
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

            byte[] iv = new byte[16];
            // GCMParameterSpec gps = new GCMParameterSpec(16 * 8, iv);
            AlgorithmParameterSpec gps = (AlgorithmParameterSpec) ctorGCMParameterSpec
                    .newInstance(16 * 8, iv);

            cp.init(Cipher.DECRYPT_MODE, key, gps);
            params = cp.getParameters();
            cp.doFinal();
        } catch (Exception ex) {
            assertTrue(true, "Passed - Cipher.doFinal() decrypt empty text throws expected exception");
            return;
        }
        assertTrue(false, "Failed - Cipher.doFinal() decrypt should have thrown exception");
    }

    @Test
    public void testAES_GCM_5() {
        try {
            // Test AES GCM Cipher Cipher.doFinal(plainTxt) on decrypt -
            // incorrect text
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

            // Encrypt the plain text
            cp.init(Cipher.ENCRYPT_MODE, key);
            params = cp.getParameters();
            cp.doFinal(plainText);

            // Verify the text
            cp.init(Cipher.DECRYPT_MODE, key, params);
            cp.doFinal(plainText);
        } catch (Exception ex) {
            if (ex.getClass().getSimpleName().equals("AEADBadTagException")) {
                assertTrue(true, "Passed - AEADBadTagException thrown on bad decrypt input");
            } else {
                assertTrue(false, "Failed - Expected AEADBadTagException:\n" + ex.getStackTrace());
            }
            return;
        }

        assertTrue(false, "Failed - Expected AEADBadTagException");
    }

    @Test
    public void testAES_GCM_Exception() throws Exception {
        // ProviderException
        try {
            // Test AES GCM Cipher
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

            // Encrypt the plain text
            //cp.init(Cipher.ENCRYPT_MODE, key);
            //params = cp.getParameters();
            cp.update(plainText);
            assertTrue(false, "Failed - Did not get expected ProviderException");
        } catch (Exception ex) {
            System.out.println("caught " + ex.getMessage());
            //ex.printStackTrace();
            if (ex instanceof IllegalStateException) {
                if (ex.getMessage().equals("Cipher not initialized")) {
                    return;
                }
                throw ex;
            } else {
                assertTrue(false, "Unexpected Exception: " + ex.getStackTrace());
                return;
            }
        }
        assertTrue(true, "Failed - Expected IllegalStateException");
    }

    @Test
    public void testAESShortBuffer() throws Exception {
        try {
            // Test AES Cipher
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

            // Encrypt the plain text
            cp.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = new byte[5];
            cp.doFinal(plainText, 0, plainText.length, cipherText);
            fail("Expected ShortBufferException did not occur");
        } catch (ShortBufferException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testAESIllegalBlockSize() throws Exception {
        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

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
        } catch (Exception ex) {
            if (ex.getClass().getSimpleName().equals("AEADBadTagException")) {
                assertTrue(true);
            } else {
                throw ex;
            }
        }
    }

    @Test
    public void testAESNull() throws Exception {
        Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
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

    @Test
    public void testIllegalParamSpec() throws Exception {
        Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

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
            fail("Expected InvalidAlgorithmParameterException");
        } catch (InvalidAlgorithmParameterException e) {
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

    @Test
    public void testArguments() throws Exception {
        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0]);
        } catch (Exception e) {
            fail("Did not expect exception on doFinal(new byte[0], 0, 0)");
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 1);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0);
            fail("Did not get expected ShortBufferException on doFinal(new byte[0], 0)");
        } catch (ShortBufferException e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 1);
            fail("Should have gotten exception on doFinal(new byte[0], 1)");
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[cp.getOutputSize(0)], 1);
            fail("Expected ShortBufferException");
        } catch (ShortBufferException e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0, 0);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 1, 0);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0, 1);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0);
        } catch (Exception e) {
            fail("Got unexpected exception on doFinal(new byte[0], 0, 0)");
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 1, 0);
            fail("Did not get expected exception on doFinal(new byte[0], 1, 0)");
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 1);
            fail("Did not get expected exception on doFinal(new byte[0], 0, 1)");
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0, 0, null);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0, new byte[0]);
            fail("Did not get expected ShortBufferException on doFinal(new byte[0], 0, 9, new byte[0])");
        } catch (ShortBufferException e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0, null, 0);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0, new byte[0], 0);
            fail("Did not get expected ShortBufferException on doFinal(new byte[0], 0, 0, new byte[0], 0)");
        } catch (ShortBufferException e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0]);
        } catch (Exception e) {
            fail("Got unexpected exception on update( new byte[0])");
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 0);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 1, 0);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 1);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0);
        } catch (Exception e) {
            fail("Got unexpected exception on update(new byte[0], 0, 0)");
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 1, 0);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 1);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 0, null);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 0, new byte[0]);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, new byte[0]);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null, 0);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null, 1);
        } catch (Exception e) {
        }

        try {
            Cipher cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, new byte[0], 0);
        } catch (Exception e) {
        }
    }

    /*
     * Checks if the given portion of b1 and b2 are equal.
     * 
     * @return true if they are equal, false if they are not equal or if the specified offsets and lengths are out of bounds. 
     */
    private boolean byteEqual(byte[] b1, int offset1, byte[] b2, int offset2, int len) {
        if ((b1.length - offset1) >= len && (b2.length - offset2) >= len) {
            for (int i = 0; i < len; i++) {
                if (b1[i + offset1] != b2[i + offset2]) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    protected boolean encryptDecrypt(Cipher cp) throws Exception {
        cp.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cp.doFinal(plainText);
        params = cp.getParameters();

        // Verify the text
        cp.init(Cipher.DECRYPT_MODE, key, params);
        byte[] newPlainText = cp.doFinal(cipherText, 0, cipherText.length);

        return byteEqual(plainText, 0, newPlainText, 0, plainText.length);
    }

    protected void encryptDecrypt(String algorithm) throws Exception {
        encryptDecrypt(algorithm, false);
    }

    protected void encryptDecrypt(String algorithm, boolean requireLengthMultipleBlockSize)
            throws Exception {
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, null);
    }

    protected void encryptDecrypt(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams) throws Exception {
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText14);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText16);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText18);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText63);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText128);
    }

    protected void encryptDecrypt(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams, byte[] message) throws Exception {
        encryptDecryptDoFinal(algorithm, requireLengthMultipleBlockSize, algParams, message);
        encryptDecryptUpdate(algorithm, requireLengthMultipleBlockSize, algParams, message);
        encryptDecryptPartialUpdate(algorithm, requireLengthMultipleBlockSize, algParams, message);
    }

    // --------------------------------------------------------------------------
    // Run encrypt/decrypt test using just doFinal calls
    //
    protected void encryptDecryptDoFinal(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams, byte[] message) throws Exception {
        Cipher cp = Cipher.getInstance(algorithm, getProviderName());
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
                assertTrue(((blockSize > 0) && (message.length % blockSize) == 0),
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length);
            }

            // Verify the text
            cp.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText = cp.doFinal(cipherText);

            boolean success = byteEqual(message, 0, newPlainText, 0, message.length);
            assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);

            // Verify the text again
            cp.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText2 = cp.doFinal(cipherText, 0, cipherText.length);

            success = byteEqual(message, 0, newPlainText2, 0, message.length);
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
            AlgorithmParameters algParams, byte[] message) throws Exception {
        Cipher cp = Cipher.getInstance(algorithm, getProviderName());
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
                assertTrue(((message.length % blockSize) == 0),
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length);
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

            boolean success = byteEqual(message, 0, newPlainText, 0, message.length);
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
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message)
            throws Exception {
        Cipher cp = Cipher.getInstance(algorithm, getProviderName());
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
                assertTrue(((message.length % blockSize) == 0),
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length);
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

            boolean success = byteEqual(message, 0, newPlainText, 0, message.length);
            assertTrue(success, "Decrypted text does not match expected, partial msglen=" + message.length);
        } catch (IllegalBlockSizeException e) {
            assertTrue((!requireLengthMultipleBlockSize || (message.length % blockSize) != 0),
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length);
        }
    }

    @Test
    public void testShortBuffer() throws Exception {
        Cipher cp = null;
        try {
            cp = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, ivBytes); //128 bit auth tag length
            cp.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
            cp.updateAAD(aadBytes);
            byte[] cipherText = new byte[5];
            cp.doFinal(plainText18, 0, plainText18.length, cipherText);
            fail("Expected ShortBufferException did not occur");
        } catch (ShortBufferException ex) {
            byte[] cipherText = new byte[18 + 16];
            cp.doFinal(plainText18, 0, plainText18.length, cipherText);

        }
    }

    @Test
    public void testEncryptAfterShortBufferRetry() throws Exception {
        Cipher cpl = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, ivBytes); //128 bit auth tag length
        try {
            cpl.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
            cpl.updateAAD(aadBytes);
            byte[] cipherText = new byte[5];
            cpl.doFinal(plainText18, 0, plainText18.length, cipherText);
            fail("Expected ShortBufferException did not occur");
        } catch (ShortBufferException ex) {
            assertTrue(true);
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unexpected Exception occurred " + e.getMessage());
        }
        // try retry with a larger buffer 
        try {
            byte[] largerCipherTextBuffer = new byte[plainText18.length + 16];
            cpl.doFinal(plainText18, 0, plainText18.length, largerCipherTextBuffer);

        } catch (Exception ex) {
            fail("Retying with larger buffer should have worked  with a larger buffer");
        }

    }

    @Test
    public void testDecryptAfterShortBufferRetry() throws Exception {
        byte[] cipherText = null;
        Cipher cpl = null;
        try {
            cpl = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            GCMParameterSpec gcmParamSpec = new GCMParameterSpec(128, ivBytes); //128 bit auth tag length

            // Encrypt the plain text
            cpl.init(Cipher.ENCRYPT_MODE, key, gcmParamSpec);
            cipherText = cpl.doFinal(plainText128, 0, plainText128.length);

            AlgorithmParameters params = cpl.getParameters();

            cpl = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cpl.init(Cipher.DECRYPT_MODE, key, params);
            byte[] sbPlainText = new byte[15];
            System.out.println("cipherText.length=" + cipherText.length);
            System.out.println("sbPlainText.length=" + sbPlainText.length);
            cpl.doFinal(cipherText, 0, cipherText.length, sbPlainText, 0);
            fail("Failed to get ShortedBufferException");
        } catch (ShortBufferException ex) {

        }
        // try retry with a larger buffer
        try {
            byte[] lbPlainTextBuffer = new byte[plainText128.length];
            cpl.doFinal(cipherText, 0, cipherText.length, lbPlainTextBuffer, 0);
            assertTrue(Arrays.equals(plainText128, lbPlainTextBuffer));
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("Retying with larger buffer should have worked  with a larger buffer");
        }

    }

    //Respecify parameters twice and it should fail. 
    public void ktestCipherStates() throws Exception {
        Cipher cpl = null;

        try {
            cpl = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            GCMParameterSpec gcmParamSpec = new GCMParameterSpec(128, ivBytes); //128 bit auth tag length
            // Encrypt the plain text

            cpl.init(Cipher.ENCRYPT_MODE, key, gcmParamSpec);
            cpl.doFinal(plainText128, 0, plainText128.length);

            try {
                cpl.init(Cipher.ENCRYPT_MODE, key, gcmParamSpec);
                cpl.doFinal(plainText128, 0, plainText128.length);
            } catch (InvalidAlgorithmParameterException e) {
                assertTrue(true);
            }
            try {
                //expected it to fail 
                cpl.doFinal(plainText128, 0, plainText128.length);
            } catch (Exception ex) {
                System.err.println("got expected exception " + ex.getMessage());
                assertTrue(true);
            }

            //Try

            cpl.init(Cipher.ENCRYPT_MODE, key);
            cpl.doFinal(plainText128, 0, plainText128.length);
            cpl.doFinal(plainText16, 0, plainText16.length);
            assert (true);

        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException
                | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
                | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            fail("Unexpected exception seen=" + e.getMessage());
        }

    }

}
