/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base.memstress;

import com.ibm.crypto.plus.provider.ChaCha20Constants;
import ibm.jceplus.junit.base.BaseTestCipher;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestMemStressChaCha20Poly1305 extends BaseTestCipher implements ChaCha20Constants {


    // 14 bytes: PASSED
    static final byte[] PLAIN_TEXT_14 = "12345678123456".getBytes();

    // 16 bytes: PASSED
    static final byte[] PLAIN_TEXT_16 = "1234567812345678".getBytes();

    // 18 bytes: PASSED
    static final byte[] PLAIN_TEXT_18 = "123456781234567812".getBytes();

    // 63 bytes: PASSED
    static final byte[] PLAIN_TEXT_63 = "123456781234567812345678123456781234567812345678123456781234567"
            .getBytes();

    // 128 bytes: PASSED
    static final byte[] PLAIN_TEXT_128 = "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            .getBytes();

    static final byte[] PLAIN_TEXT = PLAIN_TEXT_128; // default value

    static final byte[] NONCE_11_BYTE = "12345678123".getBytes();
    static final byte[] NONCE_12_BYTE = "123456781234".getBytes();
    static final byte[] NONCE_13_BYTE = "1234567812345".getBytes();

    static final byte[] BAD_TAG_16 = "BaadTaagBaadTaag".getBytes();

    static final byte[] CHACHA20_POLY1305_AAD = "ChaCha20-Poly1305 AAD".getBytes();

    static final String CHACHA20_POLY1305_ALGORITHM = "ChaCha20-Poly1305";
    static final String CHACHA20_ALGORITHM = "ChaCha20";

    static final IvParameterSpec CHACHA20_POLY1305_PARAM_SPEC = new IvParameterSpec(NONCE_12_BYTE);


    protected KeyGenerator keyGen = null;
    protected SecretKey key = null;
    protected IvParameterSpec paramSpec = null;
    protected Cipher cp = null;
    protected boolean success = true;
    protected int specifiedKeySize = 0;
    int numTimes = 100;
    boolean printheapstats = false;

    @BeforeEach
    public void setUp() throws Exception {
        keyGen = KeyGenerator.getInstance(CHACHA20_ALGORITHM, getProviderName());
        if (specifiedKeySize > 0) {
            keyGen.init(specifiedKeySize);
        }
        key = keyGen.generateKey();
        String numTimesStr = System.getProperty("com.ibm.jceplus.memstress.numtimes");
        if (numTimesStr != null) {
            numTimes = Integer.valueOf(numTimesStr);
        }
        printheapstats = Boolean
                .valueOf(System.getProperty("com.ibm.jceplus.memstress.printheapstats"));
        System.out.println("Testing ChaChaPoly1305");
    }




    //--------------------------------------------------------------------------
    // Run encrypt/decrypt test using just doFinal calls
    //
    @Test
    public void testChaCha20Poly1305EncryptDecryptDoFinalWithAAD() throws Exception {
        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;
        for (int i = 0; i < numTimes; i++) {
            try {
                cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
                cp.init(Cipher.ENCRYPT_MODE, key, CHACHA20_POLY1305_PARAM_SPEC);
                cp.updateAAD(CHACHA20_POLY1305_AAD, 0, CHACHA20_POLY1305_AAD.length);
                byte[] cipherText = cp.doFinal(PLAIN_TEXT);

                paramSpec = cp.getParameters().getParameterSpec(IvParameterSpec.class);

                // Verify the text
                cp = Cipher.getInstance(CHACHA20_POLY1305_ALGORITHM, getProviderName());
                cp.init(Cipher.DECRYPT_MODE, key, paramSpec);
                cp.updateAAD(CHACHA20_POLY1305_AAD, 0, CHACHA20_POLY1305_AAD.length);
                byte[] newPlainText = cp.doFinal(cipherText, 0, cipherText.length);

                assertTrue(Arrays.equals(PLAIN_TEXT, newPlainText));

            } catch (Exception e) {
                fail("Got unexpected exception on encrypt/decrypt...");
            }
            currentTotalMemory = rt.totalMemory();
            currentFreeMemory = rt.freeMemory();
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            prevUsedMemory = prevTotalMemory - prevFreeMemory;
            if (currentTotalMemory != prevTotalMemory || currentFreeMemory != prevFreeMemory) {
                if (printheapstats) {
                    System.out.println("ChaChaPoly1305 Iteration = " + i + " " + "Total: = "
                            + currentTotalMemory + " " + "currentUsed: = " + currentUsedMemory + " "
                            + "freeMemory: " + currentFreeMemory + " prevUsedMemory: "
                            + prevUsedMemory);
                }
                prevTotalMemory = currentTotalMemory;
                prevFreeMemory = currentFreeMemory;
            }
        }
    }



}
