/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base.memstress;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import javax.crypto.KeyAgreement;
import ibm.security.internal.spec.NamedParameterSpec;

public class BaseTestMemStressXDH extends ibm.jceplus.junit.base.BaseTest {
    /* This class by default tests "X25519" */

    int numTimes = 100;
    boolean printheapstats = false;
    String curveName = "X25519";

    //"X448";
    public BaseTestMemStressXDH(String providerName) {
        super(providerName);
    }

    public BaseTestMemStressXDH(String providerName, String curveName) {
        super(providerName);
        this.curveName = curveName;
    }

    public void setUp() throws Exception {
        String numTimesStr = System.getProperty("com.ibm.jceplus.memstress.numtimes");
        if (numTimesStr != null) {
            numTimes = Integer.valueOf(numTimesStr);
        }
        printheapstats = Boolean
                .valueOf(System.getProperty("com.ibm.jceplus.memstress.printheapstats"));
        System.out.println("Testing XDH curveName=" + curveName);
    }

    public void tearDown() throws Exception {}

    public void testXDH() throws Exception {

        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;

        for (int i = 0; i < numTimes; i++) {
            NamedParameterSpec nps = new NamedParameterSpec(this.curveName);
            compute_xdh_key(curveName, nps);
            currentTotalMemory = rt.totalMemory();
            currentFreeMemory = rt.freeMemory();
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            prevUsedMemory = prevTotalMemory - prevFreeMemory;
            if (currentTotalMemory != prevTotalMemory || currentFreeMemory != prevFreeMemory) {
                if (printheapstats) {
                    System.out.println(
                            "XDH Iteration = " + i + " " + "Total: = " + currentTotalMemory + " "
                                    + "currentUsed: = " + currentUsedMemory + " " + "freeMemory: "
                                    + currentFreeMemory + " prevUsedMemory: " + prevUsedMemory);
                }
                prevTotalMemory = currentTotalMemory;
                prevFreeMemory = currentFreeMemory;
            }
        }
    }



    void compute_xdh_key(String idString, NamedParameterSpec algParameterSpec)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchProviderException, InvalidKeyException {

        KeyPairGenerator kpgA = null;
        try {
            kpgA = KeyPairGenerator.getInstance("XDH", providerName);
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
            keyAgreeA = KeyAgreement.getInstance("XDH", providerName);
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
            kpgB = KeyPairGenerator.getInstance("XDH", providerName);
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
        //        System.out.println("KeyPairB.privKey=" + BaseUtils.bytesToHex(keyPairB.getPrivate().getEncoded()));
        //        System.out.println("KeyPairB.publicKey=" + BaseUtils.bytesToHex(keyPairB.getPublic().getEncoded()));

        KeyAgreement keyAgreeB = null;
        try {
            keyAgreeB = KeyAgreement.getInstance("XDH", providerName);
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
}

