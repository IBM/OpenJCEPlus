/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestPBECipher extends BaseTestJunit5 {
    private byte[] ivBytes = {
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    private int iterationCount = 300000;
    private byte[] salt = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    private List<String> algorithms = Arrays.asList("PBEWithHmacSHA1AndAES_128", "PBEWithHmacSHA1AndAES_256", "PBEWithHmacSHA224AndAES_128", "PBEWithHmacSHA224AndAES_256",
            "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_128", "PBEWithHmacSHA384AndAES_256",
            "PBEWithHmacSHA512AndAES_128", "PBEWithHmacSHA512AndAES_256", "PBEWithHmacSHA512/224AndAES_128", "PBEWithHmacSHA512/224AndAES_256",
            "PBEWithHmacSHA512/256AndAES_128", "PBEWithHmacSHA512/256AndAES_256", "PBEWithSHA1AndDESede", "PBEWithSHA1AndRC2_40", "PBEWithSHA1AndRC2_128", "PBEWithSHA1AndRC4_40",
            "PBEWithSHA1AndRC4_128");
    private List<String> algorithmsModePadding = Arrays.asList("PBEWithHmacSha1AndAES_128/CBC/PKCS5PAdding",
            "PBEWithHmacSha1AndAES_256/CBC/PKCS5PAdding", "PBEWithHmacSHA224andAES_128/CBC/PkCS5Padding", "PBEWithHmacSHA224andAES_256/CBC/PkCS5Padding",
            "PBEWithHmacSHA256AndAes_128/CBC/PKCS5PaddIng", "PBEWithHmacSHA256AndAes_256/CBC/PKCS5PaddIng", "PBEWithHmacSHa384AndAES_128/CbC/PKCS5Padding",
            "PBEWithHmacSHa384AndAES_256/CbC/PKCS5Padding", "PBEWithHmacSHA512andAES_128/CBc/PKCS5Padding", "PBEWithHmacSHA512andAES_256/CBc/PKCS5Padding",
            "PBEWithHmacSha512/224andAES_128/cBC/PKCS5Padding", "PBEWithHmacSha512/224andAES_256/cBC/PKCS5Padding", "PBEWithHmacShA512/256AndAES_128/CBC/pkCS5Padding",
            "PBEWithHmacShA512/256AndAES_256/CBC/pkCS5Padding", "PBEWithSHA1AndDESede/CBC/PKCS5Padding", "PBEWithSHA1AndRC2_40/CBC/PKCS5Padding", "PBEWithSHA1AndRC2_128/CBC/PKCS5Padding",
            "PBEWithSHA1AndRC4_40/ECB/NoPadding", "PBEWithSHA1AndRC4_128/ECB/NoPadding");

    private final byte[] plainText15 = "123456781234567".getBytes();
    private final byte[] plainText16 = "1234567812345678".getBytes();
    private final byte[] plainText17 = "12345678123456781".getBytes();
    private final byte[] plainText = plainText17; // default value

    @ParameterizedTest
    @FieldSource("algorithms")
    void testPBEFunctionality(String alg) throws Exception {
        SecretKey key = createKey(alg);
        encryptDecrypt(alg, key);
        encryptDecrypt(alg, key, true);
    }
    
    @ParameterizedTest
    @FieldSource("algorithmsModePadding")
    void testPBEFunctionalityModePadding(String alg) throws Exception {
        SecretKey key = createKey(alg);
        encryptDecrypt(alg, key);
        encryptDecrypt(alg, key, true);
    }

    @ParameterizedTest
    @FieldSource("algorithms")
    void testWrongMode(String alg) throws Exception {
        try {
            Cipher.getInstance(alg + "/BOB/NoPadding", getProviderName());
        } catch (NoSuchAlgorithmException e) {
            assertTrue(true);
        }

        // Interchanging modes between DESede, RC2 and RC4
        try {
            if (!alg.equals("PBEWithSHA1AndRC4_40") && !alg.equals("PBEWithSHA1AndRC4_128")) {
                Cipher.getInstance(alg + "/ECB/PKCS5Padding", getProviderName());
            }
        } catch (NoSuchAlgorithmException e) {
            assertTrue(true);
        }

        try {
            if (alg.equals("PBEWithSHA1AndRC4_40") || alg.equals("PBEWithSHA1AndRC4_128")) {
                Cipher.getInstance(alg + "/CBC/NoPadding", getProviderName());
            }
        } catch (NoSuchAlgorithmException e) {
            assertTrue(true);
        }        
    }

    @ParameterizedTest
    @FieldSource("algorithms")
    void testWrongPadding(String alg) throws Exception {
        try {
            if (!alg.equals("PBEWithSHA1AndRC4_40") && !alg.equals("PBEWithSHA1AndRC4_128")) {
                Cipher.getInstance(alg + "/CBC/BOBISO", getProviderName());
            } else {
                Cipher.getInstance(alg + "/ECB/BOBISO", getProviderName());
            }
        } catch (NoSuchPaddingException e) {
            assertTrue(true);
        }

        // Interchanging padding between DESede, RC2 and RC4
        try {
            if (!alg.equals("PBEWithSHA1AndRC4_40") && !alg.equals("PBEWithSHA1AndRC4_128")) {
                Cipher.getInstance(alg + "/CBC/NoPadding", getProviderName());
            }
        } catch (NoSuchPaddingException e) {
            assertTrue(true);
        }

        try {
            if (alg.equals("PBEWithSHA1AndRC4_40") || alg.equals("PBEWithSHA1AndRC4_128")) {
                Cipher.getInstance(alg + "/ECB/PKCS5Padding", getProviderName());
            }
        } catch (NoSuchPaddingException e) {
            assertTrue(true);
        }
    }

    @ParameterizedTest
    @FieldSource("algorithms")
    void testShortBuffer(String alg) throws Exception {
        SecretKey key = createKey(alg);
        Cipher c = Cipher.getInstance(alg, getProviderName());
        c.init(Cipher.ENCRYPT_MODE, key);
        try {
            byte[] outputBuffer = new byte[1];
            c.doFinal(plainText, 0, plainText.length, outputBuffer, 0);
            fail("Expected ShortBufferException didn't occur");
        } catch (ShortBufferException e) {
            assertTrue(true);
        }
    }

    @ParameterizedTest
    @FieldSource("algorithms")
    void testIllegalBlockSize(String alg) throws Exception {
        // RC4 is a stream cipher
        if (alg.equals("PBEWithSHA1AndRC4_40") || alg.equals("PBEWithSHA1AndRC4_128"))
            return;

        SecretKey key = createKey(alg);
        Cipher c = Cipher.getInstance(alg, getProviderName());
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = c.doFinal(plainText);
        c.init(Cipher.DECRYPT_MODE, key, c.getParameters());
        try {
            c.doFinal(cipherText, 0, cipherText.length - 1);
            fail("Expected IllegalBlockSizeException didn't occur");
        } catch (IllegalBlockSizeException e) {
            assertTrue(true);
        }
    }

    @ParameterizedTest
    @FieldSource("algorithms")
    void testWrongCipherOperatingMode(String alg) throws Exception {
        SecretKey key = createKey(alg);
        Cipher c = Cipher.getInstance(alg, getProviderName());
        try {
            c.init(-1, key);
            fail("Expected InvalidParameterException didn't occur");
        } catch (InvalidParameterException e) {
            assertTrue(true);
        }
    }

    @ParameterizedTest
    @FieldSource("algorithms")
    void testNullKeyAndPassword(String alg) throws Exception {
        SecretKey key = null;
        Cipher c = Cipher.getInstance(alg, getProviderName());
        try {
            c.init(Cipher.ENCRYPT_MODE, key);
            fail("Expected InvalidKeyException didn't occur");
        } catch (InvalidKeyException e) {
            assertTrue(true);
        }
    }

    private SecretKey createKey(String algorithm) throws Exception {
        PBEKeySpec pbeKeySpec = new PBEKeySpec("mypassword".toCharArray());
        int modeIdx = algorithm.toUpperCase(Locale.ENGLISH).indexOf("/CBC");
        modeIdx = modeIdx == -1 ? algorithm.toUpperCase(Locale.ENGLISH).indexOf("/ECB") : modeIdx;
        String keyAlgo = (modeIdx == -1 ? algorithm : algorithm.substring(0, modeIdx));
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(keyAlgo, getProviderName());
        SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);

        return pbeKey;
    }

    private void encryptDecrypt(String algorithm, SecretKey key)
            throws Exception {
        encryptDecrypt(algorithm, key, false);
    }

    private void encryptDecrypt(String algorithm, SecretKey key, boolean algParams) throws Exception {
        CompletableFuture<Void> inputData15 =  CompletableFuture.runAsync(() -> {
            try {
                encryptDecrypt(algorithm, key, algParams, plainText15);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        CompletableFuture<Void> inputData16 =  CompletableFuture.runAsync(() -> {
            try {
                encryptDecrypt(algorithm, key, algParams, plainText16);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        CompletableFuture<Void> inputData17 =  CompletableFuture.runAsync(() -> {
            try {
                encryptDecrypt(algorithm, key, algParams, plainText17);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        CompletableFuture.allOf(inputData15, inputData16, inputData17).join();
    }

    private void encryptDecrypt(String algorithm, SecretKey key, boolean algParams, byte[] message) throws Exception {
        encryptDecryptDoFinal(algorithm, key, algParams, message);
        encryptDecryptUpdate(algorithm, key, algParams, message);
        encryptDecryptPartialUpdate(algorithm, key, algParams, message);
        encryptDecryptReuseObject(algorithm, key, algParams, message);
        encryptDecryptDoFinalCopySafe(algorithm, key, algParams,
                message);
        encryptDecryptUpdateCopySafe(algorithm, key, algParams, message);
        encryptDecryptMultiUpdate(algorithm, key, algParams, message);
        wrapUnwrap(algorithm, key, algParams);
    }

    private void encryptDecryptDoFinal(String algorithm, SecretKey key, boolean algParams, byte[] message) throws Exception {
        Cipher cp = Cipher.getInstance(algorithm, getProviderName());
        if (!algParams) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount, new IvParameterSpec(ivBytes)));
        }
        byte[] cipherText = cp.doFinal(message);
        AlgorithmParameters params = cp.getParameters();

        // Verify the text
        cp = Cipher.getInstance(algorithm, getProviderName());
        cp.init(Cipher.DECRYPT_MODE, key, params);
        byte[] newPlainText = cp.doFinal(cipherText);

        boolean success = Arrays.equals(newPlainText, message);
        assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);

        // Verify the text again
        cp.init(Cipher.DECRYPT_MODE, key, params);
        byte[] newPlainText2 = cp.doFinal(cipherText, 0, cipherText.length);

        success = Arrays.equals(newPlainText2, message);
        assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);
    }

    // Run encrypt/decrypt test using just update, empty doFinal calls
    private void encryptDecryptUpdate(String algorithm, SecretKey key, boolean algParams, byte[] message) throws Exception {
                
        Cipher cp = Cipher.getInstance(algorithm, getProviderName());
        if (!algParams) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount, new IvParameterSpec(ivBytes)));
        }
        byte[] cipherText1 = cp.update(message);
        byte[] cipherText2 = cp.doFinal();
        AlgorithmParameters params = cp.getParameters();

        // Verify the text
        cp = Cipher.getInstance(algorithm, getProviderName());
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
        assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);
    }

    // Run encrypt/decrypt test with partial update
    private void encryptDecryptPartialUpdate(String algorithm, SecretKey key, boolean algParams, byte[] message)
            throws Exception {
        
        Cipher cp = Cipher.getInstance(algorithm, getProviderName());
        if (!algParams) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount, new IvParameterSpec(ivBytes)));
        }
        int partialLen = message.length > 10 ? 10 : 1;
        byte[] cipherText1 = cp.update(message, 0, partialLen);
        byte[] cipherText2 = cp.doFinal(message, partialLen, message.length - partialLen);
        AlgorithmParameters params = cp.getParameters();

        // Verify the text
        cp = Cipher.getInstance(algorithm, getProviderName());
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
        assertTrue(success, "Decrypted text does not match expected, partial msglen=" + message.length);
    }

    // Run encrypt/decrypt test reusing cipher object
    private void encryptDecryptReuseObject(String algorithm, SecretKey key, boolean algParams, byte[] message)
            throws Exception {

        Cipher cp = Cipher.getInstance(algorithm, getProviderName());
        if (!algParams) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount, new IvParameterSpec(ivBytes)));
        }
        byte[] cipherText = cp.doFinal(message);
        AlgorithmParameters params = cp.getParameters();

        // Verify that the cipher object can be used to encrypt again
        // without re-init
        byte[] cipherText2 = cp.doFinal(message);
        boolean success = Arrays.equals(cipherText2, cipherText);
        assertTrue(success, "Re-encrypted text does not match");

        // Verify the text
        cp = Cipher.getInstance(algorithm, getProviderName());
        cp.init(Cipher.DECRYPT_MODE, key, params);
        byte[] newPlainText = cp.doFinal(cipherText);
        success = Arrays.equals(newPlainText, message);
        assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);

        // Verify that the cipher object can be used to decrypt again
        // without re-init
        byte[] newPlainText2 = cp.doFinal(cipherText, 0, cipherText.length);
        success = Arrays.equals(newPlainText2, newPlainText);
        assertTrue(success, "Re-decrypted text does not match");
    }

    // Run encrypt/decrypt test using just doFinal calls (copy-safe)
    private void encryptDecryptDoFinalCopySafe(String algorithm, SecretKey key, boolean algParams, byte[] message)
            throws Exception {

        Cipher cp = Cipher.getInstance(algorithm, getProviderName());
        if (!algParams) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount, new IvParameterSpec(ivBytes)));
        }
        byte[] cipherText0 = cp.doFinal(message);

        byte[] resultBuffer = Arrays.copyOf(message, cp.getOutputSize(message.length));
        int resultLen = cp.doFinal(resultBuffer, 0, message.length, resultBuffer);
        byte[] cipherText = Arrays.copyOf(resultBuffer, resultLen);
        AlgorithmParameters params = cp.getParameters();

        boolean success = Arrays.equals(cipherText, cipherText0);
        assertTrue(success, "Encrypted text does not match expected result");

        // Verify the text
        cp = Cipher.getInstance(algorithm, getProviderName());
        cp.init(Cipher.DECRYPT_MODE, key, params);
        resultBuffer = Arrays.copyOf(cipherText, cp.getOutputSize(cipherText.length));
        resultLen = cp.doFinal(resultBuffer, 0, cipherText.length, resultBuffer);
        byte[] newPlainText = Arrays.copyOf(resultBuffer, resultLen);

        success = Arrays.equals(newPlainText, message);
        assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);
    }

    // Run encrypt/decrypt test using just update, empty doFinal calls (copy-safe)
    private void encryptDecryptUpdateCopySafe(String algorithm, SecretKey key, boolean algParams, byte[] message)
            throws Exception {

        Cipher cp = Cipher.getInstance(algorithm, getProviderName());
        if (!algParams) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount, new IvParameterSpec(ivBytes)));
        }
        byte[] cipherText0 = cp.doFinal(message);

        byte[] resultBuffer = Arrays.copyOf(message, cp.getOutputSize(message.length));
        int cipherText1Len = cp.update(resultBuffer, 0, message.length, resultBuffer);
        byte[] cipherText2 = cp.doFinal();

        byte[] cipherText = new byte[cipherText1Len + cipherText2.length];
        System.arraycopy(resultBuffer, 0, cipherText, 0, cipherText1Len);
        System.arraycopy(cipherText2, 0, cipherText, cipherText1Len, cipherText2.length);
        AlgorithmParameters params = cp.getParameters();

        boolean success = Arrays.equals(cipherText, cipherText0);
        assertTrue(success, "Encrypted text does not match expected result");

        // Verify the text
        cp = Cipher.getInstance(algorithm, getProviderName());
        cp.init(Cipher.DECRYPT_MODE, key, params);
        resultBuffer = Arrays.copyOf(cipherText, cp.getOutputSize(cipherText.length));
        int plainText1Len = cp.update(resultBuffer, 0, cipherText.length, resultBuffer);
        byte[] plainText2 = cp.doFinal();

        byte[] newPlainText = new byte[plainText1Len + plainText2.length];
        System.arraycopy(resultBuffer, 0, newPlainText, 0, plainText1Len);
        System.arraycopy(plainText2, 0, newPlainText, plainText1Len, plainText2.length);

        success = Arrays.equals(newPlainText, message);
        assertTrue(success, "Decrypted text does not match expected, msglen=" + message.length);
    }

    private void encryptDecryptMultiUpdate(String algorithm, SecretKey key, boolean algParams, byte[] message) 
            throws Exception {
        Cipher cp = Cipher.getInstance(algorithm, getProviderName());
        if (!algParams) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount, new IvParameterSpec(ivBytes)));
        }

        // Encrypting using length 4 (this value can be modified)
        byte[] cipherText = update(cp, message, 4);
        
        // Decrypting using length 5 (this value can be modified)
        cp.init(Cipher.DECRYPT_MODE, key, cp.getParameters());
        byte[] newPlainText = update(cp, cipherText, 5);

        assertArrayEquals(message, newPlainText);
       
    }

    private byte[] update(Cipher c, byte[] text, int updateLen) throws Exception {
        byte[] update1 = c.update(text, 0, updateLen);
        byte[] update2 = c.update(text, updateLen, updateLen);
        byte[] update3 = c.update(text, 2 * updateLen, text.length - (2 * updateLen));
        byte[] finalUpdate = c.doFinal();
        ByteArrayOutputStream encryptStream = new ByteArrayOutputStream();
        encryptStream.write(update1);
        encryptStream.write(update2);
        encryptStream.write(update3);
        encryptStream.write(finalUpdate);
        finalUpdate = encryptStream.toByteArray();

        return finalUpdate;
    }

    private void wrapUnwrap(String algorithm, SecretKey key, boolean algParams) throws Exception {
        Cipher cp = Cipher.getInstance(algorithm, getProviderName());
        if (!algParams) {
            cp.init(Cipher.WRAP_MODE, key);
        } else {
            cp.init(Cipher.WRAP_MODE, key, new PBEParameterSpec(salt, iterationCount, new IvParameterSpec(ivBytes)));
        }

        byte[] wrappedKey = cp.wrap(key);

        cp.init(Cipher.UNWRAP_MODE, key, cp.getParameters());
        SecretKey unwrappedKey = (SecretKey) cp.unwrap(wrappedKey, key.getAlgorithm(), Cipher.SECRET_KEY);

        assertArrayEquals(key.getEncoded(), unwrappedKey.getEncoded());
    }
}
