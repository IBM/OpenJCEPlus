/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base.memstress;

import ibm.jceplus.junit.base.BaseTest;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class BaseTestMemStressHmacSHA extends BaseTest {
    /* This test by default tests HmacSHAWith256 */

    //--------------------------------------------------------------------------
    //
    //
    static boolean warmup = false;
    int numTimes = 100;
    boolean printheapstats = false;
    String hmacAlgo = "HmacSHA256";

    // test vectors from http://www.ietf.org/proceedings/02jul/I-D/draft-ietf-ipsec-ciph-sha-256-01.txt
    final byte[] def_key_1 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
            (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b,
            (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10, (byte) 0x11,
            (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
            (byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, (byte) 0x1c, (byte) 0x1d,
            (byte) 0x1e, (byte) 0x1f, (byte) 0x20};

    //"abc".getBytes();
    final byte[] def_data_1 = {(byte) 0x61, (byte) 0x62, (byte) 0x63};

    final byte[] def_digest_1 = {(byte) 0xa2, (byte) 0x1b, (byte) 0x1f, (byte) 0x5d, (byte) 0x4c,
            (byte) 0xf4, (byte) 0xf7, (byte) 0x3a, (byte) 0x4d, (byte) 0xd9, (byte) 0x39,
            (byte) 0x75, (byte) 0x0f, (byte) 0x7a, (byte) 0x06, (byte) 0x6a, (byte) 0x7f,
            (byte) 0x98, (byte) 0xcc, (byte) 0x13, (byte) 0x1c, (byte) 0xb1, (byte) 0x6a,
            (byte) 0x66, (byte) 0x92, (byte) 0x75, (byte) 0x90, (byte) 0x21, (byte) 0xcf,
            (byte) 0xab, (byte) 0x81, (byte) 0x81};

    byte[] digest_1, data_1, key_1;



    //--------------------------------------------------------------------------
    //
    //
    public BaseTestMemStressHmacSHA(String providerName) {
        super(providerName);
        this.data_1 = def_data_1.clone();
        this.key_1 = def_key_1.clone();
        this.digest_1 = def_digest_1.clone();
        try {
            if (warmup == false) {
                warmup = true;
                warmup();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public BaseTestMemStressHmacSHA(String providerName, String digestAlgo, String hmacAlgo,
            byte[] data1, byte[] key1, byte[] digest1) {
        super(providerName);
        this.data_1 = data1.clone();
        this.key_1 = key1.clone();
        this.digest_1 = digest1.clone();
        this.hmacAlgo = hmacAlgo;
        try {
            if (warmup == false) {
                warmup = true;
                warmup();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }


    }

    //--------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {
        String numTimesStr = System.getProperty("com.ibm.jceplus.memstress.numtimes");
        if (numTimesStr != null) {
            numTimes = Integer.valueOf(numTimesStr);
        }
        printheapstats = Boolean
                .valueOf(System.getProperty("com.ibm.jceplus.memstress.printheapstats"));
        System.out.println("Testing HmacSHA " + this.hmacAlgo);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    //--------------------------------------------------------------------------
    //
    //
    public void testHmacSHA_key1() throws Exception {
        Mac mac = Mac.getInstance(this.hmacAlgo, providerName);
        SecretKeySpec key = new SecretKeySpec(key_1, this.hmacAlgo);
        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;

        for (int i = 0; i < numTimes; i++) {
            mac.init(key);
            mac.update(data_1);
            byte[] digest = mac.doFinal();

            assertTrue("Mac digest did not equal expected", Arrays.equals(digest, digest_1));
            currentTotalMemory = rt.totalMemory();
            currentFreeMemory = rt.freeMemory();
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            prevUsedMemory = prevTotalMemory - prevFreeMemory;
            if (currentTotalMemory != prevTotalMemory || currentFreeMemory != prevFreeMemory) {
                if (printheapstats) {
                    System.out.println(this.hmacAlgo + " Iteration = " + i + " " + "Total: = "
                            + currentTotalMemory + " " + "currentUsed: = " + currentUsedMemory + " "
                            + "freeMemory: " + currentFreeMemory + " prevUsedMemory: "
                            + prevUsedMemory);
                }
                prevTotalMemory = currentTotalMemory;
                prevFreeMemory = currentFreeMemory;
            }
        }
    }



    //--------------------------------------------------------------------------
    //
    //
    public void warmup() throws Exception {

        try {
            Mac mac = Mac.getInstance(this.hmacAlgo, providerName);
            SecretKeySpec key = new SecretKeySpec(key_1, this.hmacAlgo);
            for (long i = 0; i < 10000; i++) {
                mac.init(key);
                mac.update(data_1);
                mac.doFinal();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

