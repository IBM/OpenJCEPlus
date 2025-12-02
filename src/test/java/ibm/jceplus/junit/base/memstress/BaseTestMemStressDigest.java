/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base.memstress;

import ibm.jceplus.junit.base.BaseTestJunit5;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class BaseTestMemStressDigest extends BaseTestJunit5 {

    int numTimes = 100;
    boolean printheapstats = false;
    String pText = "Hello World";

    @BeforeEach
    public void setUp() throws Exception {
        String numTimesStr = System.getProperty("com.ibm.jceplus.memstress.numtimes");
        if (numTimesStr != null) {
            numTimes = Integer.valueOf(numTimesStr);
        }
        printheapstats = Boolean
                .valueOf(System.getProperty("com.ibm.jceplus.memstress.printheapstats"));
        System.out.println("Testing " + getAlgorithm());
    }

    @Test
    public void testDigestWithUpdates() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());

        for (int i = 0; i < 100000; i++)
            md.update(pText.getBytes("UTF-8"));
        md.digest();

    }

    @Test
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
                    System.out.println(getAlgorithm() + "  Iteration = " + i + " " + "Total: = "
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
            md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new IllegalArgumentException(e);
        }
        return md.digest(input);
    }

}
