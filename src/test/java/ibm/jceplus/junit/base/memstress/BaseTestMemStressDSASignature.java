/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base.memstress;

import ibm.jceplus.junit.base.BaseTestSignature;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class BaseTestMemStressDSASignature extends BaseTestSignature {

    // --------------------------------------------------------------------------
    //
    //
    static final byte[] origMsg = "this is the original message to be signed".getBytes();
    int numTimes = 100;
    boolean printheapstats = false;
    String algo = "SHA256withDSA";
    int keysize = 1024;

    // --------------------------------------------------------------------------
    //
    //
    public BaseTestMemStressDSASignature(String providerName) {
        super(providerName);
    }

    public BaseTestMemStressDSASignature(String providerName, String algo, int keySize) {
        super(providerName);
        this.algo = algo;
        this.keysize = keySize;

    }

    // --------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {
        String numTimesStr = System.getProperty("com.ibm.jceplus.memstress.numtimes");
        if (numTimesStr != null) {
            numTimes = Integer.valueOf(numTimesStr);
        }
        printheapstats = Boolean
                .valueOf(System.getProperty("com.ibm.jceplus.memstress.printheapstats"));
        System.out.println("Testing DSASignature algorithm = " + this.algo + " keySize=" + keysize);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}



    // --------------------------------------------------------------------------
    //
    //
    public void testSHAwithDSA() throws Exception {
        try {
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
                        System.out.println("DSASignature Iteration = " + i + " " + "Total: = "
                                + currentTotalMemory + " " + "currentUsed: = " + currentUsedMemory
                                + " " + "freeMemory: " + currentFreeMemory + " prevUsedMemory: "
                                + prevUsedMemory);
                    }
                    prevTotalMemory = currentTotalMemory;
                    prevFreeMemory = currentFreeMemory;
                }
            }
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }


    // --------------------------------------------------------------------------
    //
    //
    protected KeyPair generateKeyPair(int keysize) throws Exception {
        KeyPairGenerator dsaKeyPairGen = KeyPairGenerator.getInstance("DSA", providerName);
        dsaKeyPairGen.initialize(keysize);
        return dsaKeyPairGen.generateKeyPair();
    }

}
