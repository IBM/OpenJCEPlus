/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base.memstress;

import ibm.jceplus.junit.base.BaseTest;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

public class BaseTestMemStressECKeyPair extends BaseTest {

    // --------------------------------------------------------------------------
    //
    //

    static ECParameterSpec algParameterSpec;


    int numTimes = 100;
    boolean printheapstats = false;
    KeyPairGenerator kpg = null;
    KeyPairGenerator kpgc = null;
    int ecSize = 0;


    // --------------------------------------------------------------------------
    //
    //
    public BaseTestMemStressECKeyPair(String providerName) {
        super(providerName);

    }

    public BaseTestMemStressECKeyPair(String providerName, int ecSize) {
        super(providerName);
        this.ecSize = ecSize;
    }

    // --------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {
        String numTimesStr = System.getProperty("com.ibm.jceplus.memstress.numtimes");
        if (numTimesStr != null) {
            numTimes = Integer.valueOf(numTimesStr);
        }
        kpg = KeyPairGenerator.getInstance("EC", providerName);
        kpgc = KeyPairGenerator.getInstance("EC", providerName);
        printheapstats = Boolean
                .valueOf(System.getProperty("com.ibm.jceplus.memstress.printheapstats"));
        System.out.println("Testing ECKeyPair ");
    }

    // --------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    // --------------------------------------------------------------------------
    //
    //

    public void testECKeyPair() throws Exception {

        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;

        for (int i = 0; i < numTimes; i++) {
            doECKeyGen(521);
            doECKeyGenCurve("secp192k1");

            currentTotalMemory = rt.totalMemory();
            currentFreeMemory = rt.freeMemory();
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            prevUsedMemory = prevTotalMemory - prevFreeMemory;
            if (currentTotalMemory != prevTotalMemory || currentFreeMemory != prevFreeMemory) {
                if (printheapstats) {
                    System.out.println("ECKeyPair " + ecSize + " Iteration = " + i + " "
                            + "Total: = " + currentTotalMemory + " " + "currentUsed: = "
                            + currentUsedMemory + " " + "freeMemory: " + currentFreeMemory
                            + " prevUsedMemory: " + prevUsedMemory);
                }
                prevTotalMemory = currentTotalMemory;
                prevFreeMemory = currentFreeMemory;
            }
        }
    }


    public void doECKeyGen(int keypairSize) throws Exception {
        kpg.initialize(keypairSize);
        KeyPair kp = kpg.generateKeyPair();

        assert (kp != null);

        assert (kp.getPublic() != null);
        assert (kp.getPrivate() != null);

        ECPublicKey ecpu = (ECPublicKey) kp.getPublic();
        ECPrivateKey ecpr = (ECPrivateKey) kp.getPrivate();

        assert (ecpu.getW() != null);
        assert (ecpr.getS() != null);

        //System.out.println("---- EC keypair for key size " + keypairSize + "  ----");
        //System.out.println("ECPublic (x,y): (" + ecpu.getW().getAffineX() + ", " + ecpu.getW().getAffineY() + ")");
        //System.out.println("ECPrivate: " + ecpr.getS());
    }

    protected void doECKeyGenCurve(String curveName) throws Exception {
        // ECGenParameterSpec ecSpec = new ECGenParameterSpec ("secp192k1");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        kpgc.initialize(ecSpec);
        KeyPair kp = kpgc.generateKeyPair();

        assert (kp != null);

        assert (kp.getPublic() != null);
        assert (kp.getPrivate() != null);

        ECPublicKey ecpu = (ECPublicKey) kp.getPublic();
        ECPrivateKey ecpr = (ECPrivateKey) kp.getPrivate();

        assert (ecpu.getW() != null);
        assert (ecpr.getS() != null);

        //System.out.println("---- 192 test ----");
        //System.out.println("ECPublic (x,y): (" + ecpu.getW().getAffineX() + ", " + ecpu.getW().getAffineY() + ")");
        //System.out.println("ECPrivate: " + ecpr.getS());
    }

}
