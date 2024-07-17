/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base.memstress;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import ibm.jceplus.junit.base.BaseTest;

public class BaseTestMemStressDSAKeyPair extends BaseTest {

    // --------------------------------------------------------------------------
    //
    //

    static DSAParameterSpec algParameterSpec;


    int numTimes = 100;
    boolean printheapstats = false;
    protected KeyFactory dsaKeyFactory;
    int dsaSize = 2048;

    // --------------------------------------------------------------------------
    //
    //
    public BaseTestMemStressDSAKeyPair(String providerName) {
        super(providerName);

    }

    public BaseTestMemStressDSAKeyPair(String providerName, int dsaSize) {
        super(providerName);
        this.dsaSize = dsaSize;
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
        System.out.println("Testing DSAKeyPair ");
        dsaKeyFactory = KeyFactory.getInstance("DSA", providerName);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    // --------------------------------------------------------------------------
    //
    //

    public void testDSAKeyPair() throws Exception {

        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;

        for (int i = 0; i < numTimes; i++) {
            generateKeyPair(2048);
            keyFactoryCreateFromKeySpec(2048);
            keyFactoryCreateFromEncoded(2048);
            currentTotalMemory = rt.totalMemory();
            currentFreeMemory = rt.freeMemory();
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            prevUsedMemory = prevTotalMemory - prevFreeMemory;
            if (currentTotalMemory != prevTotalMemory || currentFreeMemory != prevFreeMemory) {
                if (printheapstats) {
                    System.out.println("DSAKeyPair " + dsaSize + " Iteration = " + i + " "
                            + "Total: = " + currentTotalMemory + " " + "currentUsed: = "
                            + currentUsedMemory + " " + "freeMemory: " + currentFreeMemory
                            + " prevUsedMemory: " + prevUsedMemory);
                }
                prevTotalMemory = currentTotalMemory;
                prevFreeMemory = currentFreeMemory;
            }
        }
    }

    KeyPair generateKeyPair(int size) throws Exception {


        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(size);
        KeyPair kp = kpg.generateKeyPair();
        return kp;
    }

    protected void keyFactoryCreateFromEncoded(int size) throws Exception {

        KeyPair dsaKeyPair = generateKeyPair(size);

        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(dsaKeyPair.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(
                dsaKeyPair.getPrivate().getEncoded());

        DSAPublicKey dsaPub = (DSAPublicKey) dsaKeyFactory.generatePublic(x509Spec);
        DSAPrivateKey dsaPriv = (DSAPrivateKey) dsaKeyFactory.generatePrivate(pkcs8Spec);

        if (!Arrays.equals(dsaPub.getEncoded(), dsaKeyPair.getPublic().getEncoded())) {
            fail("DSA public key does not match generated public key");
        }

        if (!Arrays.equals(dsaPriv.getEncoded(), dsaKeyPair.getPrivate().getEncoded())) {
            fail("DSA private key does not match generated public key");
        }
    }

    // --------------------------------------------------------------------------
    //
    //
    protected void keyFactoryCreateFromKeySpec(int size) throws Exception {

        KeyPair dsaKeyPair = generateKeyPair(size);

        DSAPublicKeySpec dsaPubSpec = dsaKeyFactory
                .getKeySpec(dsaKeyPair.getPublic(), DSAPublicKeySpec.class);
        DSAPublicKey dsaPub = (DSAPublicKey) dsaKeyFactory.generatePublic(dsaPubSpec);

        if (!Arrays.equals(dsaPub.getEncoded(), dsaKeyPair.getPublic().getEncoded())) {
            fail("DSA public key does not match generated public key");
        }

        DSAPrivateKeySpec dsaPrivateSpec = dsaKeyFactory
                .getKeySpec(dsaKeyPair.getPrivate(), DSAPrivateKeySpec.class);
        DSAPrivateKey dsaPriv = (DSAPrivateKey) dsaKeyFactory.generatePrivate(dsaPrivateSpec);

        if (!Arrays.equals(dsaPriv.getEncoded(), dsaKeyPair.getPrivate().getEncoded())) {
            fail("DSA private key does not match generated private key");
        }
    }
}

