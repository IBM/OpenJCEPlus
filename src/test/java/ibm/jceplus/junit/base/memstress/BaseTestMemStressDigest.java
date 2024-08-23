/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base.memstress;

import ibm.jceplus.junit.base.BaseTest;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class BaseTestMemStressDigest extends BaseTest {

    int numTimes = 100;
    boolean printheapstats = false;
    protected String digestAlg = null;
    String pText = "Hello World";

    protected void setUp() throws Exception {
        String numTimesStr = System.getProperty("com.ibm.jceplus.memstress.numtimes");
        if (numTimesStr != null) {
            numTimes = Integer.valueOf(numTimesStr);
        }
        printheapstats = Boolean
                .valueOf(System.getProperty("com.ibm.jceplus.memstress.printheapstats"));
        System.out.println("Testing " + digestAlg);
    }

    //--------------------------------------------------------------------------
    //
    //
    public BaseTestMemStressDigest(String providerName) {
        super(providerName);
        this.digestAlg = "SHA-256";
    }

    public BaseTestMemStressDigest(String providerName, String algo) {
        super(providerName);
        this.digestAlg = algo;
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testDigestWithUpdates() throws Exception {
        MessageDigest md = MessageDigest.getInstance(digestAlg, providerName);

        for (int i = 0; i < 100000; i++)
            md.update(pText.getBytes("UTF-8"));
        md.digest();

    }

    //--------------------------------------------------------------------------
    //
    //
    public void testDigest_SingleBlock() throws Exception {
        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;

        for (int i = 0; i < numTimes; i++) {
            digest(pText.getBytes("UTF-8"));
            if (i % 100000 == 0) {
                System.out.println(i);
            }


            currentTotalMemory = rt.totalMemory();
            currentFreeMemory = rt.freeMemory();
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            prevUsedMemory = prevTotalMemory - prevFreeMemory;
            if (currentTotalMemory != prevTotalMemory || currentFreeMemory != prevFreeMemory) {
                if (printheapstats) {
                    System.out.println(digestAlg + "  Iteration = " + i + " " + "Total: = "
                            + currentTotalMemory + " " + "currentUsed: = " + currentUsedMemory + " "
                            + "freeMemory: " + currentFreeMemory + " prevUsedMemory: "
                            + prevUsedMemory);
                }
                prevTotalMemory = currentTotalMemory;
                prevFreeMemory = currentFreeMemory;
            }
            i++;
        }
    }

    private byte[] digest(byte[] input) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(digestAlg, providerName);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new IllegalArgumentException(e);
        }
        return md.digest(input);
    }

}
