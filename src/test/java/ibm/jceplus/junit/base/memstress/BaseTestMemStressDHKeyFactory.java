/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base.memstress;

import ibm.jceplus.junit.base.BaseTestJunit5;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.spec.DHParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class BaseTestMemStressDHKeyFactory extends BaseTestJunit5 {



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
        System.out.println("Testing DHKeyFactory ");
    }

    @Test
    public void testDHKeyFactory() throws Exception {

        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;
 
        for (int i = 0; i < numTimes; i++) {
            keyFactoryPublicTest(2048);
            keyFactoryPrivateTest(2048);
            currentTotalMemory = rt.totalMemory();
            currentFreeMemory = rt.freeMemory();
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            prevUsedMemory = prevTotalMemory - prevFreeMemory;
            if (currentTotalMemory != prevTotalMemory || currentFreeMemory != prevFreeMemory) {
                if (printheapstats) {
                    System.out.println("DHKeyPair " + dhSize + " Iteration = " + i + " "
                            + "Total: = " + currentTotalMemory + " " + "currentUsed: = "
                            + currentUsedMemory + " " + "freeMemory: " + currentFreeMemory
                            + " prevUsedMemory: " + prevUsedMemory);
                }
                prevTotalMemory = currentTotalMemory;
                prevFreeMemory = currentFreeMemory;
            }
        }
    }

    void keyFactoryPublicTest(int size) throws Exception {

        try {

            // creating the object of KeyPairGenerator
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");

            // initializing with 1024
            kpg.initialize(1024);

            // getting key pairs
            // using generateKeyPair() method
            KeyPair kp = kpg.genKeyPair();

            // getting public key
            PublicKey prv = kp.getPublic();

            // getting byte data of Public key
            byte[] publicKeyBytes = prv.getEncoded();

            // creating keyspec object
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

            // creating object of keyfactory
            KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");

            // generating Public key from the provided key spec.
            // using generatePublic() method
            keyFactory.generatePublic(publicKeySpec);

        } catch (Exception ex) {
            ex.printStackTrace();
            throw ex;
        }
    }

    void keyFactoryPrivateTest(int size) throws Exception {

        try {

            // creating the object of KeyPairGenerator
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");

            // initializing with 1024
            kpg.initialize(1024);

            // getting key pairs
            // using generateKeyPair() method
            KeyPair kp = kpg.genKeyPair();

            // getting public key
            PrivateKey prvKey = kp.getPrivate();

            // getting byte data of Public key
            byte[] privKeyBytes = prvKey.getEncoded();

            // creating keyspec object
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);

            // creating object of keyfactory
            KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");

            // generating Public key from the provided key spec.
            // using generatePublic() method
            keyFactory.generatePrivate(privateKeySpec);

        } catch (Exception ex) {
            ex.printStackTrace();
            throw ex;
        }
    }
}
