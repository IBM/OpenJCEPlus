/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.nio.ByteBuffer;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestChaCha20Poly1305ByteBuffer extends BaseTestJunit5 {

    private static Random random = new SecureRandom();
    private static int dataSize = 4096; // see javax.crypto.CipherSpi
    private static int multiples = 3;
    private static String testVariant[] = {"HEAP_HEAP", "HEAP_DIRECT", "DIRECT_HEAP",
            "DIRECT_DIRECT"};

    static final byte[] NONCE_11_BYTE = "12345678123".getBytes();
    static final byte[] NONCE_12_BYTE = "123456781234".getBytes();
    static final byte[] NONCE_13_BYTE = "1234567812345".getBytes();
    static final byte[] BAD_TAG_16 = "BaadTaagBaadTaag".getBytes();

    static final byte[] CHACHA20_POLY1305_AAD = "12345".getBytes(); //"ChaCha20-Poly1305 AAD".getBytes();

    static final String CHACHA20_POLY1305_ALGORITHM = "ChaCha20-Poly1305";
    static final String CHACHA20_ALGORITHM = "ChaCha20";



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
}
