/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base.memstress;

import ibm.jceplus.junit.base.BaseTestJunit5;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class BaseTestMemStressDHKeyPair extends BaseTestJunit5 {



    static DHParameterSpec algParameterSpec;


    int numTimes = 100;
    boolean printheapstats = false;
    int dhSize = 2048;

    @BeforeEach
    public void setUp() throws Exception {
        String numTimesStr = System.getProperty("com.ibm.jceplus.memstress.numtimes");
        if (numTimesStr != null) {
            numTimes = Integer.valueOf(numTimesStr);
        }
        printheapstats = Boolean
                .valueOf(System.getProperty("com.ibm.jceplus.memstress.printheapstats"));
        System.out.println("Testing DHKeyPair ");
    }

    @Test
    public void testDHKeyPair() throws Exception {

        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;
        // 512-bit prime
        BigInteger dhp = new BigInteger(
                "0084F7D46A9654DA8EB0684D8F42FE52A14FDC05F70BF14AFDDD0A27B7B4C409DB4D80C2B046E0F6DCFEE29AD25CE87C6E9F81AABC4B8C6E67B5E5B203B656D3C384F7D46A9654DA8EB0684D8F42FE52A14FDC05F70BF14AFDDD0A27B7B4C409DB4D80C2B046E0F6DCFEE29AD25CE87C6E9F81AABC4B8C6E67B5E5B203B656D3C3",
                16);

        // 64-bit prime
        BigInteger dhg = new BigInteger("FE79B5403B1B14FD", 16);

        // Any number will do
        int dhl = 42;

        for (int count = 0; count < numTimes; count++) {
            generateKeyPair(2048);
            DHParameterSpec spec = new DHParameterSpec(dhp, dhg, dhl);
            generateKeyPair(dhp, dhg, dhl, spec);
            currentTotalMemory = rt.totalMemory();
            currentFreeMemory = rt.freeMemory();
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            prevUsedMemory = prevTotalMemory - prevFreeMemory;
            if (currentTotalMemory != prevTotalMemory || currentFreeMemory != prevFreeMemory) {
                if (printheapstats) {
                    System.out.println("DHKeyPair " + dhSize + " Iteration = " + count + " "
                            + "Total: = " + currentTotalMemory + " " + "currentUsed: = "
                            + currentUsedMemory + " " + "freeMemory: " + currentFreeMemory
                            + " prevUsedMemory: " + prevUsedMemory);
                }
                prevTotalMemory = currentTotalMemory;
                prevFreeMemory = currentFreeMemory;
            }
        }
    }

    @Test
    public void testDHKeyPairWithComputeSecret() throws Exception {

        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;
        // 512-bit prime
        BigInteger dhp = new BigInteger(
                "0084F7D46A9654DA8EB0684D8F42FE52A14FDC05F70BF14AFDDD0A27B7B4C409DB4D80C2B046E0F6DCFEE29AD25CE87C6E9F81AABC4B8C6E67B5E5B203B656D3C384F7D46A9654DA8EB0684D8F42FE52A14FDC05F70BF14AFDDD0A27B7B4C409DB4D80C2B046E0F6DCFEE29AD25CE87C6E9F81AABC4B8C6E67B5E5B203B656D3C3",
                16);

        // 64-bit prime
        BigInteger dhg = new BigInteger("FE79B5403B1B14FD", 16);

        // Any number will do
        int dhl = 42;

        for (int count = 0; count < numTimes; count++) {
            generateKeyPair(2048);
            DHParameterSpec spec = new DHParameterSpec(dhp, dhg, dhl);
            KeyPair kp = generateKeyPair(dhp, dhg, dhl, spec);
            PrivateKey privateKey = kp.getPrivate();
            PublicKey publicKey = kp.getPublic();
            KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman");
            ka.init(privateKey, spec);
            ka.doPhase(publicKey, true);
            byte[] secret = ka.generateSecret();
            if (count % 1000 == 0) {
                System.out.println(count + ": " + secret);
            }

            currentTotalMemory = rt.totalMemory();
            currentFreeMemory = rt.freeMemory();
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            prevUsedMemory = prevTotalMemory - prevFreeMemory;
            if (currentTotalMemory != prevTotalMemory || currentFreeMemory != prevFreeMemory) {
                if (printheapstats) {
                    System.out.println("DHKeyPair " + dhSize + " Iteration = " + count + " "
                            + "Total: = " + currentTotalMemory + " " + "currentUsed: = "
                            + currentUsedMemory + " " + "freeMemory: " + currentFreeMemory
                            + " prevUsedMemory: " + prevUsedMemory);
                }
                prevTotalMemory = currentTotalMemory;
                prevFreeMemory = currentFreeMemory;
            }
        }
    }


    KeyPair generateKeyPair(BigInteger dhp, BigInteger dhg, int dhl, DHParameterSpec spec)
            throws Exception {


        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
        kpg.initialize(spec);
        KeyPair kp = kpg.generateKeyPair();
        return kp;
    }

    KeyPair generateKeyPair(int size) throws Exception {


        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
        kpg.initialize(size);
        KeyPair kp = kpg.generateKeyPair();
        return kp;
    }
}
