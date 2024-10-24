/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */


package ibm.jceplus.junit.base;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import static org.junit.Assert.assertTrue;

public class BaseTestAESGCMCopySafe extends BaseTestJunit5 {

    private static boolean DEBUG = false;
    private static int INPUT_LENGTH = 160; // must be multiple of block size
    private static byte[] PT = new byte[INPUT_LENGTH];
    private static SecretKey KEY = null;
    private static byte[] IV = new byte[16];
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    private static int[] OFFSETS = {1, 8, 9, 16, 17, 32, 33};

    private static final String[] MODES = {"GCM"};
    protected int specifiedKeySize = 128;

    @Test
    public void testOverlappingBuffer() throws Exception {

        KEY = new SecretKeySpec(new byte[specifiedKeySize / 8], "AES");
        //Provider p = Security.getProvider("openjceplus");

        AlgorithmParameterSpec params = null;
        boolean result = true;
        for (String mode : MODES) {
            String transformation = "AES/" + mode + "/NoPadding";
            boolean isGCM = (mode.equalsIgnoreCase("GCM"));
            if (isGCM) {
                params = new GCMParameterSpec(specifiedKeySize, IV);
            }
            Cipher c = Cipher.getInstance(transformation, getProviderName());
            //System.out.println("Testing " + transformation + ":");
            for (int offset : OFFSETS) {
                //System.out.print("=> offset " + offset + ": ");
                try {
                    doTest(c, params, offset, isGCM);
                    // System.out.println("Passed");
                } catch (Exception ex) {
                    //ex.printStackTrace();
                    result = false;
                    continue;
                }
            }
        }
        if (!result) {
            assertTrue("One or more test failed", false);
        } else {
            assertTrue("Tests Passed", true);
        }
    }

    private void doTest(Cipher c, AlgorithmParameterSpec params, int offset, boolean isGCM)
            throws Exception {
        //System.out.println ("test offset = " + offset);

        // Test encryption first
        if (isGCM) {
            // re-init with only key value first to bypass the
            // Key+IV-uniqueness check for GCM encryption
            // System.out.println ("Calling first c.init with KEY(ENCRYPT_MODE)");
            c.init(Cipher.ENCRYPT_MODE, KEY);
        }
        //System.out.println ("Calling second c.init(ENCRYPT_MODE) with Key + params");
        c.init(Cipher.ENCRYPT_MODE, KEY, params);
        // System.out.println ("Calling c.doFinal(PT)" + bytesToHex(PT));
        byte[] answer = c.doFinal(PT);
        //System.out.println ("answer.length from c.doFinal(PT)" + answer.length);
        byte[] pt2 = Arrays.copyOf(PT, answer.length + offset);

        // #1: outOfs = inOfs = 0
        if (isGCM) {
            c.init(Cipher.ENCRYPT_MODE, KEY);
            c.init(Cipher.ENCRYPT_MODE, KEY, params);
        }
        // System.out.println ("calling doFinal(pt2, 0, PT.length, pt2, 0) PT.length " + PT.length +  " pt2=" + bytesToHex(pt2));
        c.doFinal(pt2, 0, PT.length, pt2, 0);
        if (!isTwoArraysEqual(pt2, 0, answer, 0, answer.length)) {
            throw new Exception("Enc#1 diff check failed!");
        } else if (DEBUG) {
            System.out.println("Enc#1 diff check passed");
        }

        // #2: inOfs = 0, outOfs = offset
        System.arraycopy(PT, 0, pt2, 0, PT.length);
        if (isGCM) {
            c.init(Cipher.ENCRYPT_MODE, KEY);
            c.init(Cipher.ENCRYPT_MODE, KEY, params);
        }
        //System.out.println ("calling doFinal(pt2, 0, PT.length, pt2, offset) PT.length " + PT.length + " offset = " + offset + " pt2=" + bytesToHex(pt2));
        c.doFinal(pt2, 0, PT.length, pt2, offset);
        if (!isTwoArraysEqual(pt2, offset, answer, 0, answer.length)) {
            throw new Exception("Enc#2 diff check failed");
        } else if (DEBUG) {
            System.out.println("Enc#2 diff check passed");
        }

        // #3: inOfs = offset, outOfs = 0
        System.arraycopy(PT, 0, pt2, offset, PT.length);
        if (isGCM) {
            c.init(Cipher.ENCRYPT_MODE, KEY);
            c.init(Cipher.ENCRYPT_MODE, KEY, params);
        }
        // System.out.println ("calling doFinal(pt2, offset, PT.length, pt2, 0) offset ="  + offset + " PT.length " + PT.length);
        c.doFinal(pt2, offset, PT.length, pt2, 0);
        if (!isTwoArraysEqual(pt2, 0, answer, 0, answer.length)) {
            throw new Exception("Enc#3 diff check failed");
        } else if (DEBUG) {
            System.out.println("Enc#3 diff check passed");
        }

        System.out.println("DECRYPTION begins");
        // Test decryption now, we should get back PT as a result
        System.out.println("cinit(DECRYPT) with KEY and Params");
        c.init(Cipher.DECRYPT_MODE, KEY, params);
        pt2 = Arrays.copyOf(answer, answer.length + offset);

        // #1: outOfs = inOfs = 0
        System.out.println("cdoFinal(pt2, 0, answer.length pt2, 0) answer.length=" + answer.length);
        c.doFinal(pt2, 0, answer.length, pt2, 0);
        if (!isTwoArraysEqual(pt2, 0, PT, 0, PT.length)) {
            throw new Exception("Dec#1 diff check failed!");
        } else if (DEBUG) {
            System.out.println("Dec#1 diff check passed");
        }

        // #2: inOfs = 0, outOfs = offset
        System.arraycopy(answer, 0, pt2, 0, answer.length);
        System.out.println("cdoFinal(pt2, 0, answer.length,pt2, offset) answer.length="
                + answer.length + " offset=" + offset);
        c.doFinal(pt2, 0, answer.length, pt2, offset);
        if (!isTwoArraysEqual(pt2, offset, PT, 0, PT.length)) {
            throw new Exception("Dec#2 diff check failed");
        } else if (DEBUG) {
            System.out.println("Dec#2 diff check passed");
        }

        // #3: inOfs = offset, outOfs = 0
        System.arraycopy(answer, 0, pt2, offset, answer.length);
        // System.out.println ("cdoFinal(pt2, offset, answer.length,pt2, 0) answer.length=" + answer.length + " offset=" + offset);
        c.doFinal(pt2, offset, answer.length, pt2, 0);
        if (!isTwoArraysEqual(pt2, 0, PT, 0, PT.length)) {
            throw new Exception("Dec#3 diff check failed");
        } else if (DEBUG) {
            System.out.println("Dec#3 diff check passed");
        }
    }

    private static boolean isTwoArraysEqual(byte[] a, int aOff, byte[] b, int bOff, int len) {
        for (int i = 0; i < len; i++) {
            if (a[aOff + i] != b[bOff + i]) {
                return false;
            }
        }
        return true;
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null)
            return new String("-null-");
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        //return new String(hexChars);
        return new String("");
    }
}

