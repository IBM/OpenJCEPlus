/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base.memstress;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import ibm.jceplus.junit.base.BaseTest;

public class BaseTestMemStressDH extends BaseTest {

    // --------------------------------------------------------------------------
    //
    //
    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    static DHParameterSpec algParameterSpec;

    static KeyPairGenerator kpgA = null;
    static KeyPairGenerator kpgB = null;

    int numTimes = 100;
    boolean printheapstats = false;
    int dhSize = 2048;

    // --------------------------------------------------------------------------
    //
    //
    public BaseTestMemStressDH(String providerName) {
        super(providerName);

    }

    public BaseTestMemStressDH(String providerName, int dhSize) {
        super(providerName);
        this.dhSize = dhSize;
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
        System.out.println("Testing DH");
    }

    // --------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    // --------------------------------------------------------------------------
    //
    //

    public void testDH() throws Exception {

        DHParameterSpec dhps = generateDHParameters(dhSize);
        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;

        for (int i = 0; i < numTimes; i++) {
            compute_dh_key(dhps);
            currentTotalMemory = rt.totalMemory();
            currentFreeMemory = rt.freeMemory();
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            prevUsedMemory = prevTotalMemory - prevFreeMemory;
            if (currentTotalMemory != prevTotalMemory || currentFreeMemory != prevFreeMemory) {
                if (printheapstats) {
                    System.out.println("DH " + dhSize + " Iteration = " + i + " " + "Total: = "
                            + currentTotalMemory + " " + "currentUsed: = " + currentUsedMemory + " "
                            + "freeMemory: " + currentFreeMemory + " prevUsedMemory: "
                            + prevUsedMemory);
                }
                prevTotalMemory = currentTotalMemory;
                prevFreeMemory = currentFreeMemory;
            }
        }
    }

    void compute_dh_key(AlgorithmParameterSpec algParameterSpec) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeyException {

        KeyPairGenerator kpgA = null;
        try {
            kpgA = KeyPairGenerator.getInstance("DH", providerName);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }

        try {
            kpgA.initialize(algParameterSpec);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw e;
        }

        KeyPair keyPairA = kpgA.generateKeyPair();

        // set up
        KeyAgreement keyAgreeA = null;
        try {
            keyAgreeA = KeyAgreement.getInstance("DH", providerName);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }
        // Two party agreement
        try {
            keyAgreeA.init(keyPairA.getPrivate());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw e;
        }
        KeyPairGenerator kpgB = null;

        try {
            kpgB = KeyPairGenerator.getInstance("DH", providerName);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }

        try

        {
            kpgB.initialize(algParameterSpec);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw e;
        }

        KeyPair keyPairB = kpgB.generateKeyPair();

        KeyAgreement keyAgreeB = null;
        try {
            keyAgreeB = KeyAgreement.getInstance("DH", providerName);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }

        try {
            keyAgreeB.init(keyPairB.getPrivate());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw e;
        }

        try {
            keyAgreeA.doPhase(keyPairB.getPublic(), true);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalStateException e) {
            e.printStackTrace();
            throw e;
        }
        try {
            keyAgreeB.doPhase(keyPairA.getPublic(), true);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw e;
        } catch (IllegalStateException e) {
            e.printStackTrace();
            throw e;
        }

        // Generate the key bytes
        byte[] sharedSecretA = keyAgreeA.generateSecret();
        byte[] sharedSecretB = keyAgreeB.generateSecret();
        assertTrue(Arrays.equals(sharedSecretA, sharedSecretB));

    }

    private DHParameterSpec generateDHParameters(int size) throws Exception {

        AlgorithmParameterGenerator algParamGen = AlgorithmParameterGenerator.getInstance("DH",
                providerName);
        algParamGen.init(size);
        AlgorithmParameters algParams = algParamGen.generateParameters();
        DHParameterSpec dhps = algParams.getParameterSpec(DHParameterSpec.class);
        return dhps;

    }

}
