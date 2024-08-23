/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import com.ibm.crypto.plus.provider.ChaCha20Constants;
import java.nio.ByteBuffer;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

public class BaseTestChaCha20Poly1305ChunkUpdate extends BaseTestCipher
        implements ChaCha20Constants {
    static final String CHACHA20_POLY1305_ALGORITHM = "ChaCha20-Poly1305";
    static final String CHACHA20_ALGORITHM = "ChaCha20";
    static final int CHACHA20_MAC_SIZE = 16;
    static final byte[] NONCE_12_BYTE = "123456781234".getBytes();
    static final IvParameterSpec CHACHA20_POLY1305_PARAM_SPEC = new IvParameterSpec(NONCE_12_BYTE);

    protected KeyGenerator keyGen = null;
    protected SecretKey key = null;
    protected int specifiedKeySize = 0;

    public BaseTestChaCha20Poly1305ChunkUpdate(String providerName) {
        super(providerName);
    }

    public void setUp() throws Exception {
        keyGen = KeyGenerator.getInstance(CHACHA20_ALGORITHM, providerName);
        if (specifiedKeySize > 0) {
            keyGen.init(specifiedKeySize);
        }
        key = keyGen.generateKey();
    }

    public void tearDown() throws Exception {}

    public void testChunks() throws Exception {
        testChunkUpdate(0);
        testChunkUpdate(1);
        testChunkUpdate(8175);
        testChunkUpdate(8176);
        testChunkUpdate(8177);
        testChunkUpdate(8178);
        testChunkUpdate(8190);
        testChunkUpdate(8191);
        testChunkUpdate(8192);
    }

    private void testChunkUpdate(int inputSize) throws Exception {
        String input = getString(inputSize);

        System.out.println("\n------------------------------------------");
        System.out.println("Input size: " + input.length());

        System.out.println("\n---Encryption---");
        byte[] cText = encrypt(input.getBytes());
        System.out.println("cText length: " + cText.length);

        ByteBuffer bb = ByteBuffer.wrap(cText);

        // cText = chacha20 ciphertext + poly1305 MAC + nonce

        byte[] originalCText = new byte[input.getBytes().length];
        byte[] nonce = new byte[ChaCha20_NONCE_SIZE];
        byte[] mac = new byte[CHACHA20_MAC_SIZE];
        bb.get(originalCText);
        bb.get(mac);
        bb.get(nonce);

        System.out.println("mac length: " + mac.length);
        System.out.println("nonce length: " + nonce.length);

        System.out.println("\n---Decryption---");
        byte[] pText = decrypt(cText, inputSize);
        System.out.println("pText length: " + pText.length);

        boolean b = new String(pText).equals(input);
        System.out.println("Status: " + b);

        assertTrue(b);
    }

    private byte[] encrypt(byte[] pText) throws Exception {
        Cipher cipher = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, providerName);
        cipher.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
        byte[] encryptedText = cipher.doFinal(pText);
        byte[] output = ByteBuffer.allocate(encryptedText.length + ChaCha20_NONCE_SIZE)
                .put(encryptedText).put(NONCE_12_BYTE).array();
        return output;
    }

    private byte[] decrypt(byte[] cText, int size) throws Exception {
        System.out.println("cText: " + cText.length);
        ByteBuffer bb = ByteBuffer.wrap(cText);
        byte[] encryptedText = new byte[cText.length - ChaCha20_NONCE_SIZE];
        byte[] nonce = new byte[ChaCha20_NONCE_SIZE];
        bb.get(encryptedText);
        bb.get(nonce);

        Cipher cipher = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, providerName);
        IvParameterSpec iv = new IvParameterSpec(nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        ByteBuffer output = ByteBuffer.allocate(size);
        ByteBuffer input = ByteBuffer.wrap(encryptedText);

        int inPos = input.position();
        int inLimit = input.limit();
        int inLen = inLimit - inPos;
        System.out.println("inLen: " + inLen);
        int outLenNeeded = cipher.getOutputSize(inLen);
        System.out.println("outLenNeeded: " + outLenNeeded);

        if (output.remaining() < outLenNeeded) {
            throw new ShortBufferException(
                    "Need at least " + outLenNeeded + " bytes of space in output buffer");
        }

        int total = 0;
        byte[] inArray, outArray;
        inArray = new byte[getTempArraySize(inLen)];
        do {
            int chunk = Math.min(inLen, inArray.length);
            if (chunk > 0) {
                input.get(inArray, 0, chunk);
            }

            if ((inLen > chunk)) {
                System.out.println("Update: inArray.length: " + inArray.length);
                System.out.println("Update: chunk: " + chunk);
                outArray = cipher.update(inArray, 0, chunk);
                System.out.println("Update: outArray.length: " + outArray.length);
                System.out.println("--------------------");
            } else {
                System.out.println("doFinal: inArray.length: " + inArray.length);
                System.out.println("doFinal: chunk: " + chunk);
                outArray = cipher.doFinal(inArray, 0, chunk);
                System.out.println("doFinal: outArray.length: " + outArray.length);
            }
            if (outArray != null && outArray.length != 0) {
                output.put(outArray);
                total += outArray.length;
            }
            inLen -= chunk;
        } while (inLen > 0);

        System.out.println("Total: " + total);
        System.out.println("Output size: " + output.array().length);
        return output.array();
    }

    private int getTempArraySize(int totalSize) {
        return Math.min(4096, totalSize);
    }

    private String getString(int size) {
        String s = "";
        for (int i = 0; i < size; i++) {
            s += "a";
        }
        return s;
    }
}
