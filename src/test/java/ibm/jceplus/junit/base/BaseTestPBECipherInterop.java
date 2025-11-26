/*
 * Copyright IBM Corp. 2025
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
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class BaseTestPBECipherInterop extends BaseTestJunit5Interop {

    private byte[] ivBytes = {
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    private int iterationCount = 300000;
    private byte[] salt = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    private String provider, interopProvider;

    @ParameterizedTest
    @MethodSource("parameters")
    public void testPBE(String algorithm, boolean suppliedParams, String provider, String interopProvider) throws Exception {
        this.provider = provider;
        this.interopProvider = interopProvider;

        SecretKey key = createKey(algorithm, provider);
        byte[] inputData = "This is an example to test PBE @%&*$#".getBytes();
        
        /* 
        * If suppliedParams = true that means Cipher will use the parameters supplied by the application
        * If suppliedParams = false that means Cipher will use default generated parameters
        */

        testCipherDifferent(algorithm, key, inputData, suppliedParams);

        testCipherUpdate(algorithm, key, inputData, suppliedParams, true, true);
        testCipherUpdate(algorithm, key, inputData, suppliedParams, true, false);
        testCipherUpdate(algorithm, key, inputData, suppliedParams, false, true);

        testCipherUpdateOutputBuffer(algorithm, key, inputData, suppliedParams, true, true);
        testCipherUpdateOutputBuffer(algorithm, key, inputData, suppliedParams, true, false);
        testCipherUpdateOutputBuffer(algorithm, key, inputData, suppliedParams, false, true);

        testCipherOutputsize(algorithm, key, inputData, suppliedParams);

        testWrap(algorithm, key, suppliedParams);

        testExceptions(algorithm, key);
    }

    // Use different Ciphers for encryption and decryption 
    private void testCipherDifferent(String algorithm, SecretKey key, byte[] inputData, boolean suppliedParams) throws Exception {
        Cipher cipherEncrypt = createCipher(Cipher.ENCRYPT_MODE, algorithm, key, suppliedParams, provider);

        byte[] cipherText = cipherEncrypt.doFinal(inputData);

        Cipher cipherDecrypt = createCipher(Cipher.DECRYPT_MODE, algorithm, key, cipherEncrypt.getParameters(), interopProvider);
        byte[] originalText = cipherDecrypt.doFinal(cipherText);

        assertArrayEquals(inputData, originalText);
    }

    private void testCipherUpdate(String algorithm, SecretKey key, byte[] inputData, boolean suppliedParams, boolean updateEncrypt, boolean updateDecrypt) 
            throws Exception {
        Cipher cipherEncrypt = createCipher(Cipher.ENCRYPT_MODE, algorithm, key, suppliedParams, provider);

        byte[] cipherText;
        if (updateEncrypt) {
            cipherText = update(cipherEncrypt, inputData, 4);
        } else {
            cipherText = cipherEncrypt.doFinal(inputData);
        }

        Cipher cipherDecrypt = createCipher(Cipher.DECRYPT_MODE, algorithm, key, cipherEncrypt.getParameters(), interopProvider);
        byte[] originalText;
        if (updateDecrypt) {
            originalText = update(cipherDecrypt, cipherText, 5);
        } else {
            originalText = cipherDecrypt.doFinal(cipherText);
        }

        assertArrayEquals(inputData, originalText);
       
    }

    private void testCipherUpdateOutputBuffer(String algorithm, SecretKey key, byte[] inputData, boolean suppliedParams, boolean updateEncrypt, boolean updateDecrypt) throws Exception {
        Cipher cipherEncrypt = createCipher(Cipher.ENCRYPT_MODE, algorithm, key, suppliedParams, provider);

        byte[] output = new byte[cipherEncrypt.getOutputSize(inputData.length) + 2];
        int encryptedLen;
        if (updateEncrypt) {
            encryptedLen = update(cipherEncrypt, inputData, 0, 4, output, 2);
        } else {
            encryptedLen = cipherEncrypt.doFinal(inputData, 0, inputData.length, output, 2);
        }
        
        Cipher cipherDecrypt = createCipher(Cipher.DECRYPT_MODE, algorithm, key, cipherEncrypt.getParameters(), interopProvider);
        byte[] original = new byte[encryptedLen];
        if (updateDecrypt) {
            update(cipherDecrypt, output, 2, 3, original, 0);
        } else {
            cipherDecrypt.doFinal(output, 2, encryptedLen, original, 0);
        }
        assertArrayEquals(inputData, Arrays.copyOf(original, inputData.length));
    }

    private void testCipherOutputsize(String algorithm, SecretKey key, byte[] inputData, boolean suppliedParams) throws Exception {
        Cipher cipher = createCipher(Cipher.ENCRYPT_MODE, algorithm, key, suppliedParams, provider);
        Cipher cipherInterop = createCipher(Cipher.ENCRYPT_MODE, algorithm, key, suppliedParams, interopProvider);

        byte[] output = new byte[cipherInterop.getOutputSize(inputData.length) + 2];
        updateOutputsize(cipher, cipherInterop, inputData, 0, 4, output, 2);
    }

    private void testWrap(String algorithm, SecretKey key, boolean suppliedParams) throws Exception {
        Cipher cipherWrap = createCipher(Cipher.WRAP_MODE, algorithm, key, suppliedParams, provider);

        byte[] wrappedKey = cipherWrap.wrap(key);

        Cipher cipherUnwrap = createCipher(Cipher.UNWRAP_MODE, algorithm, key, cipherWrap.getParameters(), interopProvider);
        SecretKey unwrappedKey = (SecretKey) cipherUnwrap.unwrap(wrappedKey, key.getAlgorithm(), Cipher.SECRET_KEY);

        assertArrayEquals(key.getEncoded(), unwrappedKey.getEncoded());
    }

    private void testExceptions(String algorithm, SecretKey key) throws Exception {
        // Testing wrong algorithm
        String providerMsg = "", interopMsg = "";
        try {
            Cipher.getInstance("wrongalgo", provider);
        } catch (NoSuchAlgorithmException e) {
            providerMsg = e.getMessage();
        }
        try {
            Cipher.getInstance("wrongalgo", interopProvider);
        } catch (NoSuchAlgorithmException e) {
            interopMsg = e.getMessage();
        }
        assertEquals(providerMsg, interopMsg);

        // Testing wrong Cipher mode during init
        try {
            Cipher c = Cipher.getInstance(algorithm, provider);
            c.init(100, key);
        } catch (InvalidParameterException e) {
            providerMsg = e.getMessage();
        }
        try {
            Cipher c = Cipher.getInstance(algorithm, interopProvider);
            c.init(100, key);
        } catch (InvalidParameterException e) {
            interopMsg = e.getMessage();
        }
        assertEquals(providerMsg, interopMsg);

        // Testing wrong key
        SecretKey wrongkey = new SecretKeySpec(new byte[5], algorithm);
        try {
            Cipher c = Cipher.getInstance(algorithm, provider);
            c.init(Cipher.ENCRYPT_MODE, wrongkey);
        } catch (InvalidKeyException e) {
            providerMsg = e.getMessage();
        }
        try {
            Cipher c = Cipher.getInstance(algorithm, interopProvider);
            c.init(Cipher.ENCRYPT_MODE, wrongkey);
        } catch (InvalidKeyException e) {
            interopMsg = e.getMessage();
        }
        assertEquals(providerMsg, interopMsg);

        // Testing a short output buffer
        boolean rc4Provider = false, rc4Interop = false;
        byte[] input = "it's raining outside today".getBytes();
        try {
            Cipher c = Cipher.getInstance(algorithm, provider);
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] output = new byte[1];
            c.doFinal(input, 0, input.length, output, 0);
        } catch (ShortBufferException e) {
            providerMsg = e.getMessage();
            rc4Provider = true;
        }
        try {
            Cipher c = Cipher.getInstance(algorithm, interopProvider);
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] output = new byte[1];
            c.doFinal(input, 0, input.length, output, 0);
        } catch (ShortBufferException e) {
            interopMsg = e.getMessage();
            rc4Interop = true;
        }
        if (algorithm.contains("RC4")) {
            assertEquals(rc4Provider, true);
            assertEquals(rc4Interop, true);
        } else {
            assertEquals(providerMsg, interopMsg);
        }

        // Testing providing wrong data to decrypt
        try {
            Cipher c = Cipher.getInstance(algorithm, provider);
            c.init(Cipher.ENCRYPT_MODE, key);
            c.doFinal(input);
            c.init(Cipher.DECRYPT_MODE, key, c.getParameters());
            c.doFinal(input);
        } catch (IllegalBlockSizeException e) {
            // Do nothing as long as correct exception is thrown
        }
        try {
            Cipher c = Cipher.getInstance(algorithm, interopProvider);
            c.init(Cipher.ENCRYPT_MODE, key);
            c.doFinal(input);
            c.init(Cipher.DECRYPT_MODE, key, c.getParameters());
            c.doFinal(input);
        } catch (IllegalBlockSizeException e) {
            // Do nothing as long as correct exception is thrown
        }
    }

    private SecretKey createKey(String algorithm, String provider) throws Exception {
        PBEKeySpec pbeKeySpec = new PBEKeySpec("mypassword".toCharArray());
        int modeIdx = algorithm.toUpperCase(Locale.ENGLISH).indexOf("/CBC");
        modeIdx = modeIdx == -1 ? algorithm.toUpperCase(Locale.ENGLISH).indexOf("/ECB") : modeIdx;
        String keyAlgo = (modeIdx == -1 ? algorithm : algorithm.substring(0, modeIdx));
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(keyAlgo, provider);
        SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);

        return pbeKey;
    }

    private Cipher createCipher(int mode, String algorithm, SecretKey pbeKey, boolean suppliedParams, String provider) throws Exception {
        Cipher c = Cipher.getInstance(algorithm, provider);
        if (suppliedParams) {
            c.init(mode, pbeKey,
                new PBEParameterSpec(salt, iterationCount,
                    new IvParameterSpec(ivBytes)));
        } else {
            c.init(mode, pbeKey);
        }

        return c;
    }

    private Cipher createCipher(int mode, String algorithm, SecretKey pbeKey, AlgorithmParameters params, String provider) throws Exception {
        Cipher c = Cipher.getInstance(algorithm, provider);
        c.init(mode, pbeKey, params);
        return c;
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

    private int update(Cipher c, byte[] text, int inputOffset, int updateLen, byte[] output, int outputOffset) throws Exception {
        int written;
        written = c.update(text, inputOffset, updateLen, output, outputOffset);
        written += c.update(text, inputOffset + updateLen, updateLen, output, outputOffset + written);
        written += c.update(text, inputOffset + (2 * updateLen), text.length - (2 * updateLen) - inputOffset, output, outputOffset + written);
        written += c.doFinal(output, written + outputOffset);

        return written;
    }

    private void updateOutputsize(Cipher cipher, Cipher cipherInterop, byte[] text, int inputOffset, int updateLen, byte[] output, int outputOffset) throws Exception {
        int written, writtenInterop;

        written = cipher.update(text, inputOffset, updateLen, output, outputOffset);
        writtenInterop = cipherInterop.update(text, inputOffset, updateLen, output, outputOffset);
        assertEquals(cipher.getOutputSize(updateLen), cipherInterop.getOutputSize(updateLen));

        written += cipher.update(text, inputOffset + updateLen, updateLen, output, outputOffset + written);
        writtenInterop += cipherInterop.update(text, inputOffset + updateLen, updateLen, output, outputOffset + writtenInterop);
        assertEquals(cipher.getOutputSize(text.length - (2 * updateLen) - inputOffset), cipherInterop.getOutputSize(text.length - (2 * updateLen) - inputOffset));

        written += cipher.update(text, inputOffset + (2 * updateLen), text.length - (2 * updateLen) - inputOffset, output, outputOffset + written);
        writtenInterop += cipherInterop.update(text, inputOffset + (2 * updateLen), text.length - (2 * updateLen) - inputOffset, output, outputOffset + writtenInterop);
        assertEquals(cipher.getOutputSize(23), cipherInterop.getOutputSize(23));
    }

    private Stream<Arguments> parameters() {
        List<String> algorithms = Arrays.asList("PBEWithHmacSHA1AndAES_128", "PBEWithHmacSHA1AndAES_256", "PBEWithHmacSHA224AndAES_128", "PBEWithHmacSHA224AndAES_256",
            "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_128", "PBEWithHmacSHA384AndAES_256",
            "PBEWithHmacSHA512AndAES_128", "PBEWithHmacSHA512AndAES_256", "PBEWithHmacSHA512/224AndAES_128", "PBEWithHmacSHA512/224AndAES_256",
            "PBEWithHmacSHA512/256AndAES_128", "PBEWithHmacSHA512/256AndAES_256", "PBEWithHmacSha1AndAES_128/CBC/PKCS5PAdding",
            "PBEWithHmacSha1AndAES_256/CBC/PKCS5PAdding", "PBEWithHmacSHA224andAES_128/CBC/PkCS5Padding", "PBEWithHmacSHA224andAES_256/CBC/PkCS5Padding",
            "PBEWithHmacSHA256AndAes_128/CBC/PKCS5PaddIng", "PBEWithHmacSHA256AndAes_256/CBC/PKCS5PaddIng", "PBEWithHmacSHa384AndAES_128/CbC/PKCS5Padding",
            "PBEWithHmacSHa384AndAES_256/CbC/PKCS5Padding", "PBEWithHmacSHA512andAES_128/CBc/PKCS5Padding", "PBEWithHmacSHA512andAES_256/CBc/PKCS5Padding",
            "PBEWithHmacSha512/224andAES_128/cBC/PKCS5Padding", "PBEWithHmacSha512/224andAES_256/cBC/PKCS5Padding", "PBEWithHmacShA512/256AndAES_128/CBC/pkCS5Padding",
            "PBEWithHmacShA512/256AndAES_256/CBC/pkCS5Padding", "PBEWithMD5AndDES", "PBEWithSHA1AndDESede", "PBEWithSHA1AndRC2_40", 
            "PBEWithSHA1AndRC2_128", "PBEWithSHA1AndRC4_40", "PBEWithSHA1AndRC4_128", "PBEWithMD5AndDES/CBC/PKCS5Padding", "PBEWithSHA1AndDESede/CBC/PKCS5Padding", 
            "PBEWithSHA1AndRC2_40/CBC/PKCS5Padding", "PBEWithSHA1AndRC2_128/CBC/PKCS5Padding", "PBEWithSHA1AndRC4_40/ECB/NoPadding", 
            "PBEWithSHA1AndRC4_128/ECB/NoPadding");

        return algorithms.stream().flatMap(algo -> Stream.of(
                Arguments.of(algo, true, getProviderName(), getInteropProviderName()),
                Arguments.of(algo, false, getProviderName(), getInteropProviderName()),
                Arguments.of(algo, true, getInteropProviderName(), getProviderName()),
                Arguments.of(algo, false, getInteropProviderName(), getProviderName())
        ));
    }
}
