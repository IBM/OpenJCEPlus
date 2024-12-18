/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base.memstress;

import ibm.jceplus.junit.base.BaseTestJunit5;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestMemStressRSAPSS2 extends BaseTestJunit5 {

    String IBM_ALG = "RSASA-PSS";

    static final String msg = "This is hello Karthik";

    private static final byte[] content3 = {(byte) 0x5F, (byte) 0x78, (byte) 0x4F, (byte) 0xC3,
            (byte) 0xE2, (byte) 0xE7, (byte) 0x65, (byte) 0xC0, (byte) 0x31, (byte) 0xF8,
            (byte) 0x97, (byte) 0x03, (byte) 0xDD, (byte) 0x71, (byte) 0x9A, (byte) 0xBD,
            (byte) 0xC5, (byte) 0x2B, (byte) 0xB1, (byte) 0x8E, (byte) 0x5F, (byte) 0x78,
            (byte) 0x4F, (byte) 0xC3, (byte) 0xE2, (byte) 0xE7, (byte) 0x65, (byte) 0xC0,
            (byte) 0x31, (byte) 0xF8, (byte) 0x97, (byte) 0x03, (byte) 0xDD, (byte) 0x71,
            (byte) 0x9A, (byte) 0xBD, (byte) 0xC5, (byte) 0x2B, (byte) 0xB1, (byte) 0x4F,
            (byte) 0xC3, (byte) 0xE2, (byte) 0xE7, (byte) 0x65, (byte) 0xC0, (byte) 0x31,
            (byte) 0xF8, (byte) 0x97, (byte) 0x03, (byte) 0xDD, (byte) 0x71, (byte) 0x9A,
            (byte) 0xBD, (byte) 0xC5, (byte) 0x2B, (byte) 0xB1, (byte) 0x8E, (byte) 0x5F,
            (byte) 0x78, (byte) 0x4F, (byte) 0xC3, (byte) 0xE2, (byte) 0xE7, (byte) 0x65,
            (byte) 0xC0, (byte) 0x31, (byte) 0xF8, (byte) 0x97, (byte) 0x03, (byte) 0xDD,
            (byte) 0x71, (byte) 0x9A, (byte) 0xBD, (byte) 0xC5, (byte) 0x2B, (byte) 0xB1,
            (byte) 0x4F, (byte) 0xC3, (byte) 0xE2, (byte) 0xE7, (byte) 0x65, (byte) 0xC0,
            (byte) 0x31, (byte) 0xF8, (byte) 0x97, (byte) 0x03, (byte) 0xDD, (byte) 0x71,
            (byte) 0x9A, (byte) 0xBD, (byte) 0xC5, (byte) 0x2B, (byte) 0xB1, (byte) 0x8E,
            (byte) 0x5F, (byte) 0x78, (byte) 0x4F, (byte) 0xC3, (byte) 0xE2, (byte) 0xE7,
            (byte) 0x65, (byte) 0xC0, (byte) 0x31, (byte) 0xF8, (byte) 0x97, (byte) 0x03,
            (byte) 0xDD, (byte) 0x71, (byte) 0x9A, (byte) 0xBD, (byte) 0xC5, (byte) 0x2B,
            (byte) 0xB1, (byte) 0x4F, (byte) 0xC3, (byte) 0xE2, (byte) 0xE7, (byte) 0x65,
            (byte) 0xC0, (byte) 0x31, (byte) 0xF8, (byte) 0x97, (byte) 0x03, (byte) 0xDD,
            (byte) 0x71, (byte) 0x9A, (byte) 0xBD, (byte) 0xC5, (byte) 0x2B, (byte) 0xB1,
            (byte) 0x8E, (byte) 0x5F, (byte) 0x78, (byte) 0x4F, (byte) 0xC3, (byte) 0xE2,
            (byte) 0xE7, (byte) 0x65, (byte) 0xC0, (byte) 0x31, (byte) 0xF8, (byte) 0x97,
            (byte) 0x03, (byte) 0xDD, (byte) 0x71, (byte) 0x9A, (byte) 0xBD, (byte) 0xC5,
            (byte) 0x2B, (byte) 0xB1};

    int numTimes = 100;
    boolean printheapstats = false;

    @BeforeAll
    public void setUp() throws Exception {
        String numTimesStr = System.getProperty("com.ibm.jceplus.memstress.numtimes");
        if (numTimesStr != null) {
            numTimes = Integer.valueOf(numTimesStr);
        }
        printheapstats = Boolean
                .valueOf(System.getProperty("com.ibm.jceplus.memstress.printheapstats"));
    }

    /**
     * Change the keysize in steps of 32 or 512 to speed up the test case Generate a
     * key once and use it for multiple tests - The OpenJCEPlusFIPS does not allow
     * keysize < 1024
     * 
     * @throws Exception
     */
    @Test
    public void testRSAPSSSignature() throws Exception {

        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", getProviderName());
        System.out.println("Testing RSAPSS keysize = " + getKeySize());
        keyGen.initialize(getKeySize(), new java.security.SecureRandom());
        KeyPair keyPair = keyGen.genKeyPair();
        PSSParameterSpec pssparamSpec = new PSSParameterSpec("SHA-1", "MGF1",
                    MGF1ParameterSpec.SHA1, 20, 1);
        try {
            for (int i = 1; i < numTimes; i++) {
                dotestSignature(content3, IBM_ALG, keyPair, pssparamSpec);
                currentTotalMemory = rt.totalMemory();
                currentFreeMemory = rt.freeMemory();
                currentUsedMemory = currentTotalMemory - currentFreeMemory;
                currentUsedMemory = currentTotalMemory - currentFreeMemory;
                prevUsedMemory = prevTotalMemory - prevFreeMemory;
                if (currentTotalMemory != prevTotalMemory || currentFreeMemory != prevFreeMemory) {
                    if (printheapstats) {
                        System.out.println("RSAPSS Iteration = " + i + " " + "Total: = "
                                + currentTotalMemory + " " + "currentUsed: = " + currentUsedMemory
                                + " " + "freeMemory: " + currentFreeMemory + " prevUsedMemory: "
                                + prevUsedMemory);
                    }
                    prevTotalMemory = currentTotalMemory;
                    prevFreeMemory = currentFreeMemory;
                }
            }

        } catch (Exception e) {

            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Helper method
     * 
     * @param content
     * @param algorithm
     * @param keyPair
     * @param pssParameterSpec
     * @throws Exception
     */

    protected void dotestSignature(byte[] content, String algorithm, KeyPair keyPair,
            PSSParameterSpec pssParameterSpec) throws Exception {

        Signature sig = Signature.getInstance(algorithm, getProviderName());
        if (pssParameterSpec != null) {
            // System.out.println ("calling sig.setParameter");
            sig.setParameter(pssParameterSpec);
        }
        sig.initSign(keyPair.getPrivate());
        sig.update(content);
        byte[] sigBytes = sig.sign();

        // Verify the signature
        sig.initVerify(keyPair.getPublic());
        sig.update(content);

        // Check Signature
        // Signature verifySig = Signature.getInstance("SHA1withRSA/PSS", getProviderName());
        // verifySig.initVerify(cert);
        // verifySig.update(content);
        boolean signatureVerified = sig.verify(sigBytes);

        assertTrue(signatureVerified, "signature is invalid!!");
    }
}
