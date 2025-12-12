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
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class BaseTestPBECipher extends BaseTestJunit5 {

    private byte[] ivBytes = {
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    private int iterationCount = 300000;
    private byte[] salt = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    @ParameterizedTest
    @MethodSource("parameters")
    public void testPBE(String algorithm, boolean suppliedParams) throws Exception {
        SecretKey key = createKey(algorithm);
        byte[] inputData = "This is an example to test PBE @%&*$#".getBytes();
        
        /* 
        * If suppliedParams = true that means Cipher will use the parameters supplied by the application
        * If suppliedParams = false that means Cipher will use default generated parameters
        */

        testCipher(algorithm, key, inputData, suppliedParams);

        testCipherDifferent(algorithm, key, inputData, suppliedParams);

        testCipherUpdate(algorithm, key, inputData, suppliedParams, true, true);
        testCipherUpdate(algorithm, key, inputData, suppliedParams, true, false);
        testCipherUpdate(algorithm, key, inputData, suppliedParams, false, true);

        // Testing with outputOffset = 2, can be modified
        testCipherUpdateOutputBuffer(algorithm, key, inputData, 2, suppliedParams, true, true);
        testCipherUpdateOutputBuffer(algorithm, key, inputData, 2, suppliedParams, true, false);
        testCipherUpdateOutputBuffer(algorithm, key, inputData, 2, suppliedParams, false, true);

        testWrap(algorithm, key, suppliedParams);
    }

    // Use the same Cipher for encryption and decryption 
    private void testCipher(String algorithm, SecretKey key, byte[] inputData, boolean suppliedParams) throws Exception {
        Cipher cipher = createCipher(Cipher.ENCRYPT_MODE, algorithm, key, suppliedParams);

        byte[] cipherText = cipher.doFinal(inputData);

        cipher.init(Cipher.DECRYPT_MODE, key, cipher.getParameters());
        byte[] originalText = cipher.doFinal(cipherText);

        assertArrayEquals(inputData, originalText);
    }

    // Use different Ciphers for encryption and decryption 
    private void testCipherDifferent(String algorithm, SecretKey key, byte[] inputData, boolean suppliedParams) throws Exception {
        Cipher cipherEncrypt = createCipher(Cipher.ENCRYPT_MODE, algorithm, key, suppliedParams);

        byte[] cipherText = cipherEncrypt.doFinal(inputData);

        Cipher cipherDecrypt = createCipher(Cipher.DECRYPT_MODE, algorithm, key, cipherEncrypt.getParameters());
        byte[] originalText = cipherDecrypt.doFinal(cipherText);

        assertArrayEquals(inputData, originalText);
    }

    private void testCipherUpdate(String algorithm, SecretKey key, byte[] inputData, boolean suppliedParams, boolean updateEncrypt, boolean updateDecrypt) 
            throws Exception {
        Cipher cipher = createCipher(Cipher.ENCRYPT_MODE, algorithm, key, suppliedParams);

        byte[] cipherText;
        if (updateEncrypt) {
            cipherText = update(cipher, inputData, 4);
        } else {
            cipherText = cipher.doFinal(inputData);
        }

        cipher.init(Cipher.DECRYPT_MODE, key, cipher.getParameters());
        byte[] originalText;
        if (updateDecrypt) {
            originalText = update(cipher, cipherText, 5);
        } else {
            originalText = cipher.doFinal(cipherText);
        }

        assertArrayEquals(inputData, originalText);
       
    }
 
    private void testCipherUpdateOutputBuffer(String algorithm, SecretKey key, byte[] inputData, int outputOffset, boolean suppliedParams, boolean updateEncrypt, boolean updateDecrypt) throws Exception {
        Cipher cipher = createCipher(Cipher.ENCRYPT_MODE, algorithm, key, suppliedParams);

        byte[] output = new byte[cipher.getOutputSize(inputData.length) + outputOffset];
        int encryptedLen;
        if (updateEncrypt) {
            encryptedLen = update(cipher, inputData, 0, 4, output, outputOffset);
        } else {
            encryptedLen = cipher.doFinal(inputData, 0, inputData.length, output, outputOffset);
        }
        cipher.init(Cipher.DECRYPT_MODE, key, cipher.getParameters());
        byte[] original = new byte[encryptedLen];
        if (updateDecrypt) {
            update(cipher, output, outputOffset, 3, original, 0);
        } else {
            cipher.doFinal(output, outputOffset, encryptedLen, original, 0);
        }
        assertArrayEquals(inputData, Arrays.copyOf(original, inputData.length));
    }

    private void testWrap(String algorithm, SecretKey key, boolean suppliedParams) throws Exception {
        Cipher cipher = createCipher(Cipher.WRAP_MODE, algorithm, key, suppliedParams);

        byte[] wrappedKey = cipher.wrap(key);

        cipher.init(Cipher.UNWRAP_MODE, key, cipher.getParameters());
        SecretKey unwrappedKey = (SecretKey) cipher.unwrap(wrappedKey, key.getAlgorithm(), Cipher.SECRET_KEY);

        assertArrayEquals(key.getEncoded(), unwrappedKey.getEncoded());
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

    private Cipher createCipher(int mode, String algorithm, SecretKey pbeKey, boolean suppliedParams) throws Exception {
        Cipher c = Cipher.getInstance(algorithm, getProviderName());
        if (suppliedParams) {
            c.init(mode, pbeKey,
                new PBEParameterSpec(salt, iterationCount,
                    new IvParameterSpec(ivBytes)));
        } else {
            c.init(mode, pbeKey);
        }

        return c;
    }

    private Cipher createCipher(int mode, String algorithm, SecretKey pbeKey, AlgorithmParameters params) throws Exception {
        Cipher c = Cipher.getInstance(algorithm, getProviderName());
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
                Arguments.of(algo, true),
                Arguments.of(algo, false)
        ));
    }
}
