/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base.memstress;

import ibm.jceplus.junit.base.BaseTestCipher;
import java.security.AlgorithmParameters;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestMemStressAES extends BaseTestCipher {

    Random r = new Random(5);
    static int iteration = 0;
    static final byte[] plainText1024 = new byte[1024];
    static final byte[] plainText16 = "12345678".getBytes();
    protected SecretKey key = null;
    protected AlgorithmParameters params = null;
    protected Cipher cp = null;
    protected boolean success = true;
    protected int specifiedKeySize = 0;
    static int numTimes = 100;
    boolean printheapstats = false;
    byte[] encodedKey = null;
    KeyGenerator keyGenerator = null;
    SecretKey keyFromIBMJCE = null;

    @BeforeEach
    public void setUp() throws Exception {

        this.specifiedKeySize = getKeySize();
        encodedKey = new byte[specifiedKeySize / 8];
        r.nextBytes(plainText1024);

        //key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        keyGenerator = KeyGenerator.getInstance("AES", getProviderName());
        keyGenerator.init(this.specifiedKeySize);
        keyFromIBMJCE = keyGenerator.generateKey();

        String numTimesStr = System.getProperty("com.ibm.jceplus.memstress.numtimes");
        if (numTimesStr != null) {
            numTimes = Integer.valueOf(numTimesStr);
        }

        printheapstats = Boolean
                .valueOf(System.getProperty("com.ibm.jceplus.memstress.printheapstats"));
        System.out.println("Testing AES " + this.specifiedKeySize);
    }

    @Test
    public void testAES() throws Exception {
        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;
        String algorithms[] = {"AES", "AES/CFB128/NoPadding", "AES/CTR/PKCS5Padding",
                "AES/ECB/NoPadding", "AES/CBC/PKCS5Padding"};

        for (int i = 0; i < numTimes; i++) {

            key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
            for (int j = 0; j < algorithms.length; j++) {
                encryptDecryptData(algorithms[j]);
                currentTotalMemory = rt.totalMemory();
                currentFreeMemory = rt.freeMemory();
                currentUsedMemory = currentTotalMemory - currentFreeMemory;
                prevUsedMemory = prevTotalMemory - prevFreeMemory;
                if (currentTotalMemory != prevTotalMemory || currentFreeMemory != prevFreeMemory) {
                    if (printheapstats) {
                        System.out.println("AES " + this.specifiedKeySize + " Iteration = " + i
                                + " " + "Total: = " + currentTotalMemory + " " + "currentUsed: = "
                                + currentUsedMemory + " " + "freeMemory: " + currentFreeMemory
                                + " prevUsedMemory: " + prevUsedMemory);
                    }
                    prevTotalMemory = currentTotalMemory;
                    prevFreeMemory = currentFreeMemory;
                }
            }
        }
    }



    private void encryptDecryptData(String algorithm) throws Exception {
        byte[] clearText = {(byte) 0x0, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x10,
                (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15};

        SecretKeyFactory kf = SecretKeyFactory.getInstance("AES", getProviderName());
        //test KeyFactory routines.
        kf.translateKey(keyFromIBMJCE);

        byte[] cipherData = null;
        AlgorithmParameters params = null;
        // Encrypt once

        Cipher cipher = Cipher.getInstance(algorithm, getProviderName());

        cipher.init(Cipher.ENCRYPT_MODE, key);

        params = cipher.getParameters();

        cipherData = cipher.doFinal(clearText);
        assertTrue(cipherData != null);
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        byte[] plainTextDecrypted = cipher.doFinal(cipherData);
        assertTrue(Arrays.equals(clearText, plainTextDecrypted));
    } // end encryptDecryptData()
}
