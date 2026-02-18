/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Random;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestChaCha20Poly1305ByteBuffer extends BaseTestJunit5 {

    private static Random random = new SecureRandom();
    private static int dataSize = 4096; // see javax.crypto.CipherSpi
    private static int multiples = 3;
    private static String testVariant[] = {"HEAP_HEAP", "HEAP_DIRECT", "DIRECT_HEAP",
            "DIRECT_DIRECT"};

    private static final byte[] NONCE_11_BYTE = "12345678123".getBytes();
    private static final byte[] NONCE_12_BYTE = "123456781234".getBytes();
    private static final byte[] NONCE_13_BYTE = "1234567812345".getBytes();
    private static final byte[] BAD_TAG_16 = "BaadTaagBaadTaag".getBytes();

    private static final byte[] CHACHA20_POLY1305_AAD = "12345".getBytes(); //"ChaCha20-Poly1305 AAD".getBytes();

    private static final String CHACHA20_POLY1305_ALGORITHM = "ChaCha20-Poly1305";
    private static final String CHACHA20_ALGORITHM = "ChaCha20";


    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] TEST_KEY_BYTES = HEX.parseHex(
            "3cb1283912536e4108c3094dc2940d0d020afbd7701de267bbfb359bc7d54dd7");
    private static final byte[] TEST_NONCE_BYTES = HEX.parseHex(
            "9bd647a43b6fa7826e2cc26d");
    private static final byte[] TEST_AAD_BYTES =
            "This is a bunch of additional data to throw into the mix.".
                    getBytes(StandardCharsets.UTF_8);
    private static final byte[] TEST_INPUT_BYTES =
        "This is a plaintext message".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TEST_CT_BYTES = HEX.parseHex(
            "8536c999809f4b9d6a1594ee1084c751d1bd8a991e6a4b4ac26386f04b9a1303" +
            "f40cbe6788d72af2d0c617");
    private static final ByteBuffer EXPOUTBUF = ByteBuffer.wrap(TEST_CT_BYTES);

    protected KeyGenerator keyGen = null;
    protected SecretKey key = null;
    protected IvParameterSpec paramSpec = null;
    protected Cipher cp = null;
    protected boolean success = true;
    protected int specifiedKeySize = 0;

    @BeforeEach
    public void setUp() throws Exception {
        keyGen = KeyGenerator.getInstance(CHACHA20_ALGORITHM, getProviderName());
        if (specifiedKeySize > 0) {
            keyGen.init(specifiedKeySize);
        }
        //key = keyGen.generateKey();
    }

    @Test
    public void testByteBuffer() throws Exception {
        Cipher cipher = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
        System.out.println("Testing " + cipher.getProvider());

        boolean failedOnce = false;
        Exception failedReason = null;

        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);
        byte[] dataChunk = new byte[dataSize];
        random.nextBytes(dataChunk);

        // re-use key bytes as IV as the real test is buffer calculation

        /*
         * Iterate through various sizes to make sure that the code works with
         * internal temp buffer size 4096.
         */
        for (int t = 1; t <= multiples; t++) {
            int size = t * dataSize;

            System.out.println("\nTesting data size: " + size);

            try {
                decrypt(cipher, dataChunk, t,

                        ByteBuffer.allocate(dataSize), ByteBuffer.allocate(size),
                        ByteBuffer.allocateDirect(dataSize), ByteBuffer.allocateDirect(size));
            } catch (ProviderException pe) {
                pe.printStackTrace();
                System.out.println("\tFailed with data size " + size);
                failedOnce = true;
                failedReason = pe;
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("\tFailed with data size " + size);
                failedOnce = true;
                failedReason = e;
            }
        }
        if (failedOnce) {
            failedReason.printStackTrace();
            assertTrue(false);
        }
        System.out.println("\n=> Passed...");
        assertTrue(true);
    }

    //    private enum VariantTest {
    //        HEAP_HEAP, HEAP_DIRECT, DIRECT_HEAP, DIRECT_DIRECT
    //    };

    private void decrypt(Cipher cipher, byte[] dataChunk, int multiples, ByteBuffer heapIn,
            ByteBuffer heapOut, ByteBuffer directIn, ByteBuffer directOut) throws Exception {

        //System.out.println ("dataChunk.length=" + dataChunk.length);
        //System.out.println ("multiples=" + multiples);

        ByteBuffer inBB = null;
        ByteBuffer outBB = null;

        // try various combinations of input/output
        for (int i = 0; i < testVariant.length; i++) {
            byte nonce12[] = new byte[12];
            random.nextBytes(nonce12);
            key = keyGen.generateKey();
            IvParameterSpec ivSpec = new IvParameterSpec(nonce12);
            System.out.println(" " + testVariant[i]);

            switch (testVariant[i]) {
                case "HEAP_HEAP":
                    inBB = heapIn;
                    outBB = heapOut;
                    break;
                case "HEAP_DIRECT":
                    inBB = heapIn;
                    outBB = directOut;
                    break;
                case "DIRECT_HEAP":
                    inBB = directIn;
                    outBB = heapOut;
                    break;
                case "DIRECT_DIRECT":
                    inBB = directIn;
                    outBB = directOut;
                    break;
            }

            // prepare input and output buffers
            inBB.clear();
            inBB.put(dataChunk);

            outBB.clear();

            try {
                // Always re-init the Cipher object so cipher is in
                // a good state for future testing
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

                for (int j = 0; j < multiples; j++) {
                    inBB.flip();
                    int len = cipher.update(inBB, outBB);
                    System.out.println("len=" + len);
                    if (inBB.hasRemaining()) {
                        throw new Exception("buffer not empty");
                    }
                }
                // finish decryption and process all data buffered
                cipher.doFinal(inBB, outBB);
                throw new RuntimeException("Error: doFinal completed without exception");
            } catch (AEADBadTagException ex) {
                System.out.println("Expected AEADBadTagException thrown");
                continue;
            } catch (Exception ex) {
                ex.printStackTrace();
                throw ex;
            }
        }
    }

    @Test
    public void testUpdateAAD() throws Exception {
        ByteBuffer twoKBuf = ByteBuffer.allocate(2048);
        ByteBuffer nonBABuf = ByteBuffer.allocate(1329);

        /* Test 1: Make an array backed buffer that is 16-byte
         * aligned, treat all data as AAD and feed it to
         * updateAAD.
         */
        aadUpdateTest(twoKBuf);

        /* Test 2: Use the same buffer, but place the offset such
         * that the remaining data is not block aligned.
         */
        aadUpdateTest(twoKBuf.position(395));

        /* Test 3: Make a buffer of non-block aligned size with an
         * offset that keeps the remaining data non-block
         * aligned.
         */
        aadUpdateTest(nonBABuf.position(602));

        /* Test 4: Use a buffer of block aligned size, but slice
         * the buffer such that the slice offset is part
         * way into the original buffer.
         */
        aadUpdateTest(twoKBuf.rewind().slice(1024, 1024).position(42));

        /* Test 5: Try the same test as #4, this time with
         * non-block aligned buffers/slices.
         */
        aadUpdateTest(nonBABuf.rewind().slice(347, 347).position(86));

        /* Test 6: Make a ByteBuffer from an array-backed
         * MemorySegment, and try updating.
         */
        MemorySegment mseg = MemorySegment.ofArray(new byte[2048]);
        ByteBuffer msegBuf = mseg.asByteBuffer();
        aadUpdateTest(msegBuf.position(55));

        /* Test 7: Use a slice from the MemorySegment and create a
         * buffer from that for testing.
         */
        MemorySegment msegSlice = mseg.asSlice(1024);
        aadUpdateTest(msegSlice.asByteBuffer().position(55));

        /* Test 8: Create a slice from the ByteBuffer from the
         * original MemorySegment.
         */
        aadUpdateTest(msegBuf.rewind().slice(1024, 1024));

        /* Test 9: Place the AAD, followed by plaintext and verify
         * the ciphertext.
         */
        // Create a ByteBuffer where the AAD and plaintext actually sit
        // somewhere in the middle of the underlying array, with non-test-vector
        // memory on either side of the data.
        ByteBuffer vectorBuf = ByteBuffer.allocate(1024).position(600)
                                         .put(TEST_AAD_BYTES).put(TEST_INPUT_BYTES)
                                         .flip().position(600);
        vectorTest(vectorBuf);

        /* Test 10: Perform the same test, this time on a slice
         * of the test vector buffer.
         */
        ByteBuffer vectorSlice = vectorBuf.slice(600,
                TEST_AAD_BYTES.length + TEST_INPUT_BYTES.length);
        vectorTest(vectorSlice);
    }


    // Simple test for taking a ByteBuffer and throwing all
    // remaining bytes into an updateAAD call.
    private void aadUpdateTest(ByteBuffer buffer) throws Exception {
        SecretKey key = keyGen.generateKey();
        byte[] nonce = new byte[12];
        random.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305", getProviderName());
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));

        cipher.updateAAD(buffer);
        // Per the API the buffer's position and limit should be equal
        if (buffer.position() != buffer.limit()) {
            throw new RuntimeException("Buffer position and limit " +
                    "should be equal but are not: p = " +
                    buffer.position() + ", l = " + buffer.limit());
        }
    }

    // Test for making sure that the updateAAD method, when
    // put in with a complete encryption operation still gets the
    // expected answer.
    private void vectorTest(ByteBuffer buffer) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(TEST_KEY_BYTES, "ChaCha20"),
                new IvParameterSpec(TEST_NONCE_BYTES));
        ByteBuffer outbuf = ByteBuffer.allocate(cipher.getOutputSize(
                TEST_INPUT_BYTES.length));

        // Adjust the limit to be the end of the aad
        int origLim = buffer.limit();
        buffer.limit(buffer.position() + TEST_AAD_BYTES.length);
        cipher.updateAAD(buffer);
        buffer.limit(origLim);
        cipher.doFinal(buffer, outbuf);
        if (!outbuf.flip().equals(EXPOUTBUF)) {
            throw new RuntimeException("Output data mismatch");
        }
    }
}
