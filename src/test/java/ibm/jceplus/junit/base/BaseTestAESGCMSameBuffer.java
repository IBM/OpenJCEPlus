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
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.junit.jupiter.api.Test;

/*
 * @test
 * @bug 8048596
 * @summary Check if AEAD operations work correctly when buffers used
 *          for storing plain text and cipher text are overlapped or the same
 */
public class BaseTestAESGCMSameBuffer extends BaseTestJunit5 {

    private static final String AES = "AES";
    private static final String GCM = "GCM";
    private static final String PADDING = "NoPadding";
    private static final int OFFSET = 2;
    private static final int OFFSETS = 4;
    private static final int KEY_LENGTHS[] = {128, 192, 256};
    private static final int TEXT_LENGTHS[] = {0, 1024};
    private static final int AAD_LENGTHS[] = {0, 1024};

    private SecretKey key;
    private String transformation;
    private int textLength;
    private int AADLength;

    @Test
    public void testAESGCMSameBuffer() throws Exception {
        for (int keyLength : KEY_LENGTHS) {
            for (int textLength : TEXT_LENGTHS) {
                for (int AADLength : AAD_LENGTHS) {
                    for (int i = 0; i < OFFSETS; i++) {
                        // try different offsets
                        int offset = i * OFFSET;
                        do_runTest(AES, GCM, PADDING, keyLength, textLength, AADLength, offset);
                    }
                }
            }
        }
    }

    /*
     * Run single test case with given parameters
     */
    void do_runTest(String algo, String mode, String padding, int keyLength, int textLength,
            int AADLength, int offset) throws Exception {
        /* System.out.println("Testing " + keyLength + " key length; "
                + textLength + " text lenght; " + AADLength + " AAD length; "
                + offset + " offset"); */
        if (keyLength > Cipher.getMaxAllowedKeyLength(algo)) {
            // skip this if this key length is larger than what's
            // configured in the jce jurisdiction policy files
            return;
        }

        // init a secret key
        KeyGenerator kg = KeyGenerator.getInstance(algo, getProviderName());
        kg.init(keyLength);
        key = kg.generateKey();

        this.transformation = algo + "/" + mode + "/" + padding;
        this.textLength = textLength;
        this.AADLength = AADLength;

        /*
         * There are four test cases:
         *   1. AAD and text are placed in separated byte arrays
         *   2. AAD and text are placed in the same byte array
         *   3. AAD and text are placed in separated byte buffers
         *   4. AAD and text are placed in the same byte buffer
         */
        Cipher ci = this.createCipher(Cipher.ENCRYPT_MODE, null);
        AlgorithmParameters params = ci.getParameters();
        this.doTestWithSeparateArrays(offset, params);
        this.doTestWithSameArrays(offset, params);
        this.doTestWithSeparatedBuffer(offset, params);
        this.doTestWithSameBuffer(offset, params);
    }

    /*
     * Run the test in case when AAD and text are placed in separated byte
     * arrays.
     */
    private void doTestWithSeparateArrays(int offset, AlgorithmParameters params) throws Exception {
        // prepare buffers to test
        Cipher c = createCipher(Cipher.ENCRYPT_MODE, params);
        int outputLength = c.getOutputSize(textLength);
        int outputBufSize = outputLength + offset * 2;

        byte[] inputText = BaseUtils.generateBytes(outputBufSize);
        byte[] AAD = BaseUtils.generateBytes(AADLength);

        // do the test
        runGCMWithSeparateArray(Cipher.ENCRYPT_MODE, AAD, inputText, offset * 2, textLength, offset,
                params);
        int tagLength = c.getParameters().getParameterSpec(GCMParameterSpec.class).getTLen() / 8;
        runGCMWithSeparateArray(Cipher.DECRYPT_MODE, AAD, inputText, offset, textLength + tagLength,
                offset, params);
    }

    /**
     * Run the test in case when AAD and text are placed in the same byte
     * array.
     */
    private void doTestWithSameArrays(int offset, AlgorithmParameters params) throws Exception {
        // prepare buffers to test
        Cipher c = createCipher(Cipher.ENCRYPT_MODE, params);
        int outputLength = c.getOutputSize(textLength);
        int outputBufSize = AADLength + outputLength + offset * 2;

        byte[] AAD_and_text = BaseUtils.generateBytes(outputBufSize);

        // do the test
        runGCMWithSameArray(Cipher.ENCRYPT_MODE, AAD_and_text, AADLength + offset, textLength,
                params);
        int tagLength = c.getParameters().getParameterSpec(GCMParameterSpec.class).getTLen() / 8;
        runGCMWithSameArray(Cipher.DECRYPT_MODE, AAD_and_text, AADLength + offset,
                textLength + tagLength, params);
    }

    /*
     * Run the test in case when AAD and text are placed in separated ByteBuffer
     */
    private void doTestWithSeparatedBuffer(int offset, AlgorithmParameters params)
            throws Exception {
        // prepare AAD byte buffers to test
        byte[] AAD = BaseUtils.generateBytes(AADLength);
        ByteBuffer AAD_Buf = ByteBuffer.allocate(AADLength);
        AAD_Buf.put(AAD, 0, AAD.length);
        AAD_Buf.flip();

        // prepare text byte buffer to encrypt/decrypt
        Cipher c = createCipher(Cipher.ENCRYPT_MODE, params);
        int outputLength = c.getOutputSize(textLength);
        int outputBufSize = outputLength + offset;
        byte[] inputText = BaseUtils.generateBytes(outputBufSize);
        ByteBuffer plainTextBB = ByteBuffer.allocateDirect(inputText.length);
        plainTextBB.put(inputText);
        plainTextBB.position(offset);
        plainTextBB.limit(offset + textLength);

        // do test
        runGCMWithSeparateBuffers(Cipher.ENCRYPT_MODE, AAD_Buf, plainTextBB, offset, textLength,
                params);
        int tagLength = c.getParameters().getParameterSpec(GCMParameterSpec.class).getTLen() / 8;
        plainTextBB.position(offset);
        plainTextBB.limit(offset + textLength + tagLength);
        runGCMWithSeparateBuffers(Cipher.DECRYPT_MODE, AAD_Buf, plainTextBB, offset,
                textLength + tagLength, params);
    }

    /*
     * Run the test in case when AAD and text are placed in the same ByteBuffer
     */
    private void doTestWithSameBuffer(int offset, AlgorithmParameters params) throws Exception {
        // calculate output length
        Cipher c = createCipher(Cipher.ENCRYPT_MODE, params);
        int outputLength = c.getOutputSize(textLength);

        // prepare byte buffer contained AAD and plain text
        int bufSize = AADLength + offset + outputLength;
        byte[] AAD_and_Text = BaseUtils.generateBytes(bufSize);
        ByteBuffer AAD_and_Text_Buf = ByteBuffer.allocate(bufSize);
        AAD_and_Text_Buf.put(AAD_and_Text, 0, AAD_and_Text.length);

        // do test
        runGCMWithSameBuffer(Cipher.ENCRYPT_MODE, AAD_and_Text_Buf, offset, textLength, params);
        int tagLength = c.getParameters().getParameterSpec(GCMParameterSpec.class).getTLen() / 8;
        AAD_and_Text_Buf.limit(AADLength + offset + textLength + tagLength);
        runGCMWithSameBuffer(Cipher.DECRYPT_MODE, AAD_and_Text_Buf, offset, textLength + tagLength,
                params);

    }

    /*
     * Execute GCM encryption/decryption of a text placed in a byte array.
     * AAD is placed in the separated byte array.
     * Data are processed twice:
     *   - in a separately allocated buffer
     *   - in the text buffer
     * Check if two results are equal
     */
    private void runGCMWithSeparateArray(int mode, byte[] AAD, byte[] text, int txtOffset,
            int lenght, int offset, AlgorithmParameters params) throws Exception {
        // first, generate the cipher text at an allocated buffer
        Cipher cipher = createCipher(mode, params);
        cipher.updateAAD(AAD);
        byte[] outputText = cipher.doFinal(text, txtOffset, lenght);

        // new cipher for encrypt operation
        Cipher anotherCipher = createCipher(mode, params);
        anotherCipher.updateAAD(AAD);

        // next, generate cipher text again at the same buffer of plain text
        int myoff = offset;
        int off = anotherCipher.update(text, txtOffset, lenght, text, myoff);
        anotherCipher.doFinal(text, myoff + off);

        // check if two resutls are equal
        if (!isEqual(text, myoff, outputText, 0, outputText.length)) {
            throw new RuntimeException("Two results not equal, mode:" + mode);
        }
    }

    /*
     * Execute GCM encrption/decryption of a text. The AAD and text to process
     * are placed in the same byte array. Data are processed twice:
     *   - in a separetly allocated buffer
     *   - in a buffer that shares content of the AAD_and_Text_BA
     * Check if two results are equal
     */
    private void runGCMWithSameArray(int mode, byte[] array, int txtOffset, int length,
            AlgorithmParameters params) throws Exception {
        // first, generate cipher text at an allocated buffer
        Cipher cipher = createCipher(mode, params);
        cipher.updateAAD(array, 0, AADLength);
        byte[] outputText = cipher.doFinal(array, txtOffset, length);

        // new cipher for encrypt operation
        Cipher anotherCipher = createCipher(mode, params);
        anotherCipher.updateAAD(array, 0, AADLength);

        // next, generate cipher text again at the same buffer of plain text
        int off = anotherCipher.update(array, txtOffset, length, array, txtOffset);
        anotherCipher.doFinal(array, txtOffset + off);

        // check if two results are equal or not
        if (!isEqual(array, txtOffset, outputText, 0, outputText.length)) {
            throw new RuntimeException("Two results are not equal, mode:" + mode);
        }
    }

    /*
     * Execute GCM encryption/decryption of textBB. AAD and text to process are
     * placed in different byte buffers. Data are processed twice:
     *  - in a separately allocated buffer
     *  - in a buffer that shares content of the textBB
     * Check if results are equal
     */
    private void runGCMWithSeparateBuffers(int mode, ByteBuffer buffer, ByteBuffer textBB,
            int txtOffset, int dataLength, AlgorithmParameters params) throws Exception {
        // take offset into account
        textBB.position(txtOffset);
        textBB.mark();

        // first, generate the cipher text at an allocated buffer
        Cipher cipher = createCipher(mode, params);
        cipher.updateAAD(buffer);
        buffer.flip();
        ByteBuffer outBB = ByteBuffer.allocateDirect(cipher.getOutputSize(dataLength));

        cipher.doFinal(textBB, outBB); // get cipher text in outBB
        outBB.flip();

        // restore positions
        textBB.reset();

        // next, generate cipher text again in a buffer that shares content
        Cipher anotherCipher = createCipher(mode, params);
        anotherCipher.updateAAD(buffer);
        buffer.flip();
        ByteBuffer buf2 = textBB.duplicate(); // buf2 shares textBuf context
        buf2.limit(txtOffset + anotherCipher.getOutputSize(dataLength));
        int dataProcessed2 = anotherCipher.doFinal(textBB, buf2);
        buf2.position(txtOffset);
        buf2.limit(txtOffset + dataProcessed2);

        if (!buf2.equals(outBB)) {
            throw new RuntimeException("Two results are not equal, mode:" + mode);
        }
    }

    /*
     * Execute GCM encryption/decryption of text. AAD and a text to process are
     * placed in the same buffer. Data is processed twice:
     *   - in a separately allocated buffer
     *   - in a buffer that shares content of the AAD_and_Text_BB
     */
    private void runGCMWithSameBuffer(int mode, ByteBuffer buffer, int txtOffset, int length,
            AlgorithmParameters params) throws Exception {


        // allocate a separate buffer
        Cipher cipher = createCipher(mode, params);
        ByteBuffer outBB = ByteBuffer.allocateDirect(cipher.getOutputSize(length));

        // first, generate the cipher text at an allocated buffer
        buffer.flip();
        buffer.limit(AADLength);
        cipher.updateAAD(buffer);
        buffer.limit(AADLength + txtOffset + length);
        buffer.position(AADLength + txtOffset);
        cipher.doFinal(buffer, outBB);
        outBB.flip(); // cipher text in outBB

        // next, generate cipherText again in the same buffer
        Cipher anotherCipher = createCipher(mode, params);
        buffer.flip();
        buffer.limit(AADLength);
        anotherCipher.updateAAD(buffer);
        buffer.limit(AADLength + txtOffset + length);
        buffer.position(AADLength + txtOffset);

        // share textBuf context
        ByteBuffer buf2 = buffer.duplicate();
        buf2.limit(AADLength + txtOffset + anotherCipher.getOutputSize(length));
        int dataProcessed2 = anotherCipher.doFinal(buffer, buf2);
        buf2.position(AADLength + txtOffset);
        buf2.limit(AADLength + txtOffset + dataProcessed2);

        if (!buf2.equals(outBB)) {
            throw new RuntimeException("Two results are not equal, mode:" + mode);
        }
    }

    private boolean isEqual(byte[] A, int offsetA, byte[] B, int offsetB, int bytesToCompare) {
        //System.out.println("offsetA: " + offsetA + " offsetB: " + offsetA
        //        + " bytesToCompare: " + bytesToCompare);
        for (int i = 0; i < bytesToCompare; i++) {
            int setA = i + offsetA;
            int setB = i + offsetB;
            if (setA > A.length - 1 || setB > B.length - 1 || A[setA] != B[setB]) {
                return false;
            }
        }

        return true;
    }

    /*
     * Creates a Cipher object for testing: for encryption it creates new Cipher
     * based on previously saved parameters (it is prohibited to use the same
     * Cipher twice for encription during GCM mode), or returns initiated
     * existing Cipher.
     */
    private Cipher createCipher(int mode, AlgorithmParameters params) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation, getProviderName());
        if (Cipher.ENCRYPT_MODE == mode) {
            // initiate it with the saved parameters
            if (params != null) {
                cipher.init(Cipher.ENCRYPT_MODE, key, params);
            } else {
                // intiate the cipher and save parameters
                cipher.init(Cipher.ENCRYPT_MODE, key);
            }
        } else if (cipher != null) {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
        } else {
            throw new RuntimeException("Can't create cipher");
        }

        return cipher;
    }

}
