/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base.memstress;

import ibm.jceplus.junit.base.BaseTestJunit5;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class BaseTestMemStressMLKEM extends BaseTestJunit5 {

    // --------------------------------------------------------------------------
    //
    //
    int numTimes = 100;
    boolean printheapstats = false;

    String algo = "ML-KEM";

    // --------------------------------------------------------------------------
    //
    //
    public void setPrintheapstats(boolean printheapstats) {
        this.printheapstats = printheapstats;
    }

    public boolean getPrintheapstats() {
        return printheapstats;
    }

    public void setNumTimes(Integer numTimes) {
        this.numTimes = numTimes;
    }

    public Integer getNumTimes() {
        return numTimes;
    }

    public String getAlgo() {
        return algo;
    }

    // --------------------------------------------------------------------------
    //
    //
    @ParameterizedTest
    @ValueSource(strings = {"ML-KEM", "ML-KEM-512", "ML_KEM_512", "MLKEM512",
        "OID.2.16.840.1.101.3.4.4.1", "2.16.840.1.101.3.4.4.1", "ML-KEM-768", "ML_KEM_768",
        "MLKEM768", "OID.2.16.840.1.101.3.4.4.2", "2.16.840.1.101.3.4.4.2", "ML-KEM-1024",
        "ML_KEM_1024", "MLKEM1024", "OID.2.16.840.1.101.3.4.4.3", "2.16.840.1.101.3.4.4.3" })
    public void testMLKEM(String algorithmName) throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            // This is not in the FIPS provider yet.
            return;
        }

        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;

        for (int i = 0; i < numTimes; i++) {
            doMLKEMSecret(algorithmName);

            currentTotalMemory = rt.totalMemory();
            currentFreeMemory = rt.freeMemory();

            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            prevUsedMemory = prevTotalMemory - prevFreeMemory;

            if (currentTotalMemory != prevTotalMemory
                || currentFreeMemory != prevFreeMemory) {
                if (printheapstats) {
                    System.out.println(algorithmName + " "
                        + " Iteration = " + i + " "
                        + "Total: = " + currentTotalMemory + " "
                        + "currentUsed: = " + currentUsedMemory + " "
                        + "freeMemory: " + currentFreeMemory
                        + " prevUsedMemory: " + prevUsedMemory);
                }
                prevTotalMemory = currentTotalMemory;
                prevFreeMemory = currentFreeMemory;
            }
        }
        System.out.println("Done");
    }

    private void doMLKEMSecret(String algorithm) throws Exception {
        KeyPairGenerator kpgForA = null;

        try {
            kpgForA = KeyPairGenerator.getInstance(algorithm, getProviderName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }

        KEM kem = KEM.getInstance(algorithm, getProviderName());

        KeyPair keyPairForA = kpgForA.generateKeyPair();

        KEM.Encapsulator encr = kem.newEncapsulator(keyPairForA.getPublic());
        KEM.Encapsulated enc = encr.encapsulate(0, 31, "AES");

        SecretKey keyE = enc.key();

        KEM.Decapsulator decr = kem.newDecapsulator(keyPairForA.getPrivate());
        SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 31, "AES");

        assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
    }
}
