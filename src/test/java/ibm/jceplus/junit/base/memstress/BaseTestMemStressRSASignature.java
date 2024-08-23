/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base.memstress;

import ibm.jceplus.junit.base.BaseTestSignature;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class BaseTestMemStressRSASignature extends BaseTestSignature {

    //--------------------------------------------------------------------------
    //
    //
    static final byte[] origMsg = "this is the original message to be signed".getBytes();
    int numTimes = 100;
    boolean printheapstats = false;
    String algo = "SHA256withRSA";
    int keysize = 1024;


    //--------------------------------------------------------------------------
    //
    //
    public BaseTestMemStressRSASignature(String providerName) {
        super(providerName);
    }

    //
    //
    public BaseTestMemStressRSASignature(String providerName, String algo, int keysize) {
        super(providerName);
        this.algo = algo;
        this.keysize = keysize;
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
        System.out.println("Testing RSASignature algo=" + this.algo + " keysize=" + this.keysize);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}


    //--------------------------------------------------------------------------
    //
    //
    public void testRSASignature() throws Exception {
        KeyPair keyPair = generateKeyPair(this.keysize);
        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;
        for (int i = 0; i < numTimes; i++) {
            doSignVerify(this.algo, origMsg, keyPair.getPrivate(), keyPair.getPublic());
            currentTotalMemory = rt.totalMemory();
            currentFreeMemory = rt.freeMemory();
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            prevUsedMemory = prevTotalMemory - prevFreeMemory;
            if (currentTotalMemory != prevTotalMemory || currentFreeMemory != prevFreeMemory) {
                if (printheapstats) {
                    System.out.println("RSASignature Iteration = " + i + " " + "Total: = "
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
    protected KeyPair generateKeyPair(int keysize) throws Exception {
        KeyPairGenerator rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", providerName);
        rsaKeyPairGen.initialize(keysize);
        return rsaKeyPairGen.generateKeyPair();
    }



}

