/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.nio.ByteBuffer;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import static org.junit.Assert.assertTrue;

public class BaseTestAESGCMWithByteBuffer extends BaseTestJunit5 {

    private static Random random = new SecureRandom();
    private static int dataSize = 4096; // see javax.crypto.CipherSpi
    private static int multiples = 3;
    private static String testVariant[] = {"HEAP_HEAP", "HEAP_DIRECT", "DIRECT_HEAP",
            "DIRECT_DIRECT"};

    @Test
    public void testAESGCMWithByteBuffer() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        System.out.println("Testing " + cipher.getProvider());

        boolean failedOnce = false;
        Exception failedReason = null;

        int tagLen = 96; // in bits
        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);
        byte[] dataChunk = new byte[dataSize];
        random.nextBytes(dataChunk);

        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        // re-use key bytes as IV as the real test is buffer calculation
        GCMParameterSpec s = new GCMParameterSpec(tagLen, keyBytes);

        /*
         * Iterate through various sizes to make sure that the code works with
         * internal temp buffer size 4096.
         */
        for (int t = 1; t <= multiples; t++) {
            int size = t * dataSize;

            System.out.println("\nTesting data size: " + size);

            try {
                decrypt(cipher, key, s, dataChunk, t, ByteBuffer.allocate(dataSize),
                        ByteBuffer.allocate(size), ByteBuffer.allocateDirect(dataSize),
                        ByteBuffer.allocateDirect(size));
            } catch (ProviderException pe) {
                System.out.println("\tFailed with data size " + size);
                failedOnce = true;
                failedReason = pe;
            } catch (Exception e) {
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

    private void decrypt(Cipher cipher, SecretKey key, GCMParameterSpec s, byte[] dataChunk,
            int multiples, ByteBuffer heapIn, ByteBuffer heapOut, ByteBuffer directIn,
            ByteBuffer directOut) throws Exception {

        //System.out.println ("dataChunk.length=" + dataChunk.length);
        //System.out.println ("multiples=" + multiples);

        ByteBuffer inBB = null;
        ByteBuffer outBB = null;

        // try various combinations of input/output
        for (int i = 0; i < testVariant.length; i++) {
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
                cipher.init(Cipher.DECRYPT_MODE, key, s);

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
