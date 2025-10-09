/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */


package ibm.jceplus.junit.base;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestAESCopySafe extends BaseTestJunit5 {

    private static final boolean DEBUG = false;
    private static final int INPUT_LENGTH = 32; // should be a multiple of block size
    private byte[] workingBuffer = new byte[INPUT_LENGTH + 512]; // Add plenty of room in our working buffer for overlap.
    private SecretKey KEY = null;

    private int[] OFFSETS = {0, 7, 8, 16, 32};

    enum MODE { CBC, GCM }

    protected int specifiedKeySize = 128;

    @Test
    public void testOverlappingBuffer() throws Exception {

        Assumptions.assumeTrue(javax.crypto.Cipher.getMaxAllowedKeyLength("AES") >= specifiedKeySize);

        KEY = new SecretKeySpec(new byte[specifiedKeySize / 8], "AES");

        for (MODE mode : MODE.values()) {
            String transformation = "AES/" + mode.toString() + "/NoPadding";
            Cipher c = Cipher.getInstance(transformation, getProviderName());
            System.out.println("Testing " + transformation + " from provider: " + getProviderName());
            for (int inputOffset : OFFSETS) {
                for (int outputOffset : OFFSETS) {
                    System.out.println("Mode: " + mode + " inputOffset: " + inputOffset + " outputOffset: " + outputOffset);
                    System.out.println("Testing doFinal");
                    doTest(c, inputOffset, outputOffset, mode, false);
                    if (mode == MODE.CBC) {
                        System.out.println("Testing update");
                        doTest(c, inputOffset, outputOffset, mode, true);
                    }
                }
            }
        }
    }

    private void doTest(Cipher c, int inputOffset, int outputOffset, MODE mode, boolean isUpdate)
            throws Exception {
        byte[] clearText = new byte[INPUT_LENGTH];
        Arrays.fill(clearText, 0, INPUT_LENGTH, (byte) 0x01);
        System.arraycopy(clearText, 0, workingBuffer, 0, INPUT_LENGTH);

        // Get baseline encrypted value. This baseline will be used through the rest of the 
        // test to be a known answer for cipher text.
        initCipher(c, mode, true);
        if (DEBUG) {
            System.out.println("Calling c." + (isUpdate ? "update" : "doFinal") + "(workingBuffer, 0, INPUT_LENGTH)");
            System.out.println("    INPUT_LENGTH: " + INPUT_LENGTH);
            System.out.println("    workingBuffer:\n" + BaseUtils.bytesToHex(workingBuffer));
        }
        byte[] cipherText = null;
        if (isUpdate) {
            cipherText = c.update(workingBuffer, 0, INPUT_LENGTH);
        } else {
            cipherText = c.doFinal(workingBuffer, 0, INPUT_LENGTH);
        }
        if (DEBUG) {
            System.out.println("cipherText:\n" + BaseUtils.bytesToHex(cipherText));
            System.out.println ("cipherText.length: " + cipherText.length);
        }

        // A GCM cipher must be reinitialized since the IV is typically not supposed to be reused. This
        // test however expects a deterministic encrypted value in order to evaluate if the operation
        // worked as expected.
        initCipher(c, mode, true);

        System.arraycopy(clearText, 0, workingBuffer, inputOffset, INPUT_LENGTH);
        if (DEBUG) {
            System.out.println("Testing encryption.");
            System.out.println ("Calling c." + (isUpdate ? "update" : "doFinal") + "(workingBuffer, inputOffset, INPUT_LENGTH, workingBuffer, outputOffset)");
            System.out.println("    inputOffset:" + inputOffset);
            System.out.println("    INPUT_LENGTH:" + INPUT_LENGTH);
            System.out.println("    outputOffset:" + outputOffset);
            System.out.println("    workingBuffer:\n" + BaseUtils.bytesToHex(workingBuffer));
        }
        if (isUpdate) {
            c.update(workingBuffer, inputOffset, INPUT_LENGTH, workingBuffer, outputOffset);
        } else {
            c.doFinal(workingBuffer, inputOffset, INPUT_LENGTH, workingBuffer, outputOffset);
        }
        if (DEBUG) {
            System.out.println("workingBuffer:\n" + BaseUtils.bytesToHex(workingBuffer));
        }
        
        assertArrayEquals(Arrays.copyOfRange(workingBuffer, outputOffset, outputOffset + cipherText.length), cipherText, "Encryption check failed.");
        if (DEBUG) {
            System.out.println("Encrypt check passed.");
        }

        // Test decryption now, we should get back the original clear text value as a result.
        if (DEBUG) {
            System.out.println("c.init(DECRYPT) with KEY and Params");
        }
        initCipher(c, mode, false);

        Arrays.fill(workingBuffer, 0, INPUT_LENGTH, (byte) 0x00);
        System.arraycopy(cipherText, 0, workingBuffer, inputOffset, cipherText.length);

        if (DEBUG) {
            System.out.println("Testing decryption.");
            System.out.println("Calling c." + (isUpdate ? "update" : "doFinal") + "(workingBuffer, inputOffset, cipherText.length, workingBuffer, outputOffset)");
            System.out.println("    inputOffset: " + inputOffset);
            System.out.println("    cipherText.length: " + cipherText.length);
            System.out.println("    outputOffset: " + outputOffset);
            System.out.println("    workingBuffer:\n" + BaseUtils.bytesToHex(workingBuffer));
        }
        if (isUpdate) {
            c.update(workingBuffer, inputOffset, cipherText.length, workingBuffer, outputOffset);
        } else {
            c.doFinal(workingBuffer, inputOffset, cipherText.length, workingBuffer, outputOffset);
        }
        if (DEBUG) {
            System.out.println("New Clear Text:\n" + BaseUtils.bytesToHex(workingBuffer));
        }
        assertArrayEquals(Arrays.copyOfRange(workingBuffer, outputOffset, outputOffset + clearText.length), clearText, "Decryption check failed.");
        if (DEBUG) {
            System.out.println("Decrypt check passed.");
        }

        // Zero the working buffer just for ease of debug.
        Arrays.fill(clearText, 0, INPUT_LENGTH, (byte) 0x00);
    }

    private void initCipher(Cipher c, MODE mode, boolean isEncrypt)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

        byte[] IV = new byte[16];

        if (mode == MODE.GCM) {
            AlgorithmParameterSpec params = new GCMParameterSpec(specifiedKeySize, IV);
            // Re-initialize with only key value first to bypass the
            // key+IV uniqueness check for GCM encryption.
            if (isEncrypt) {
                c.init(Cipher.ENCRYPT_MODE, KEY);
                c.init(Cipher.ENCRYPT_MODE, KEY, params);
            } else {
                c.init(Cipher.DECRYPT_MODE, KEY, params);
            }
        } else if (mode == MODE.CBC) {
            IvParameterSpec spec = new IvParameterSpec(IV);
            if (isEncrypt) {
                c.init(Cipher.ENCRYPT_MODE, KEY, spec);
            } else {
                c.init(Cipher.DECRYPT_MODE, KEY, spec);
            }
        } else {
            fail("Unexpected mode value.");
        }
    }
}
