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
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Assume;

public class BaseTestMemStressAES extends BaseTestCipher {

    Random r = new Random(5);
    static int iteration = 0;
    static final byte[] plainText1024 = new byte[1024];
    static final byte[] plainText16 = "12345678".getBytes();

    //--------------------------------------------------------------------------
    //
    //
    static boolean warmup = false;
    protected SecretKey key = null;
    protected AlgorithmParameters params = null;
    protected Cipher cp = null;
    protected boolean success = true;
    protected int specifiedKeySize = 0;
    static int numTimes = 100;
    boolean printheapstats = false;
    int DEFAULT_KEYSIZE = 256;
    byte[] encodedKey = null;
    KeyGenerator keyGenerator = null;
    SecretKey keyFromIBMJCE = null;



    //--------------------------------------------------------------------------
    //
    //
    public BaseTestMemStressAES(String providerName) {
        super(providerName);
        this.specifiedKeySize = DEFAULT_KEYSIZE;
        try {
            if (warmup == false) {
                warmup = true;
                warmup();
            }
        } catch (Exception e) {
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public BaseTestMemStressAES(String providerName, int keySize) throws Exception {
        super(providerName);
        this.specifiedKeySize = keySize;

        Assume.assumeTrue(javax.crypto.Cipher.getMaxAllowedKeyLength("AES") >= keySize);

        try {
            if (warmup == false) {
                warmup = true;
                warmup();
            }
        } catch (Exception e) {
        }

    }

    //--------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {

        encodedKey = new byte[(specifiedKeySize > 0 ? specifiedKeySize : 128) / 8];
        r.nextBytes(plainText1024);

        //key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        keyGenerator = KeyGenerator.getInstance("AES", "OpenJCEPlus");
        keyGenerator.init(DEFAULT_KEYSIZE);
        keyFromIBMJCE = keyGenerator.generateKey();

        String numTimesStr = System.getProperty("com.ibm.jceplus.memstress.numtimes");
        if (numTimesStr != null) {
            numTimes = Integer.valueOf(numTimesStr);
        }

        printheapstats = Boolean
                .valueOf(System.getProperty("com.ibm.jceplus.memstress.printheapstats"));
        System.out.println("Testing AES " + this.specifiedKeySize);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    //--------------------------------------------------------------------------
    //
    //
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

    //--------------------------------------------------------------------------
    //
    //

    private void encryptDecryptData(String algorithm) throws Exception {
        byte[] clearText = {(byte) 0x0, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x10,
                (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15};

        SecretKeyFactory kf = SecretKeyFactory.getInstance("AES", providerName);
        //test KeyFactory routines.
        kf.translateKey(keyFromIBMJCE);

        byte[] cipherData = null;
        AlgorithmParameters params = null;
        // Encrypt once

        Cipher cipher = Cipher.getInstance(algorithm, providerName);

        cipher.init(Cipher.ENCRYPT_MODE, key);

        params = cipher.getParameters();

        cipherData = cipher.doFinal(clearText);
        assertTrue(cipherData != null);
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        byte[] plainTextDecrypted = cipher.doFinal(cipherData);
        assertTrue(Arrays.equals(clearText, plainTextDecrypted));
    } // end encryptDecryptData()



    //--------------------------------------------------------------------------
    // warmup functions for enable fastjni
    //
    static public void warmup() throws Exception {
        java.security.Provider java_provider = null;
        int modeInt;
        boolean stream = false;
        SecretKeySpec skey;
        int key_size = 128;
        byte[] skey_bytes = new byte[key_size / 8];
        int len = 4096;
        byte[] iv;
        byte[] data = plainText16;
        byte[] out;
        Cipher cipher;
        Random r;
        try {
            java_provider = java.security.Security.getProvider("OpenJCEPlus");
            if (java_provider == null) {
                java_provider = new com.ibm.crypto.plus.provider.OpenJCEPlus();
                java.security.Security.insertProviderAt(java_provider, 1);
            }

            r = new Random(10);
            String mode = "encrypt_stream";
            String cipherMode = "AES/CBC/NoPadding";

            if (mode.contains("encrypt"))
                modeInt = 1;
            else if (mode.contains("decrypt"))
                modeInt = 0;
            else
                throw new RuntimeException("Unsupported mode");

            if (mode.contains("block"))
                stream = false;
            else if (mode.contains("stream"))
                stream = true;
            else
                throw new RuntimeException("block mode or stream mode must be specified");

            r.nextBytes(skey_bytes);
            skey = new SecretKeySpec(skey_bytes, "AES");


            for (int i = 0; i < numTimes; i++) {
                cipher = Cipher.getInstance(cipherMode, java_provider);
                out = new byte[len];
                iv = new byte[16];
                r.nextBytes(iv);
                AlgorithmParameterSpec iviv = new IvParameterSpec(iv);

                if (modeInt == 0)
                    cipher.init(Cipher.DECRYPT_MODE, skey, iviv);
                else
                    cipher.init(Cipher.ENCRYPT_MODE, skey, iviv);
                if (stream) {
                    for (long j = 0; j < 9; j++)
                        cipher.update(data, 0, data.length, out);
                } else {
                    for (long k = 0; k < 9; k++) {
                        cipher.update(data, 0, data.length, out);
                        // cipher.doFinal();
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
