/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import org.junit.jupiter.api.Test;
import static org.junit.Assert.assertTrue;

public class BaseTestTruncatedDigest extends BaseTestJunit5Signature {

    String IBM_ALG = "RSAPSS";

    private static final byte[] content = {(byte) 0x5F, (byte) 0x78, (byte) 0x4F, (byte) 0xC3,
            (byte) 0xE2, (byte) 0xE7, (byte) 0x65, (byte) 0xC0, (byte) 0x31, (byte) 0xF8,
            (byte) 0x97, (byte) 0x03, (byte) 0xDD, (byte) 0x71, (byte) 0x9A, (byte) 0xBD,
            (byte) 0xC5, (byte) 0x2B, (byte) 0xB1, (byte) 0x8E};

    private static final byte[] content1 = {(byte) 0x5F, (byte) 0x78, (byte) 0x4F, (byte) 0xC3,
            (byte) 0xE2, (byte) 0xE7, (byte) 0x65, (byte) 0xC0, (byte) 0x31, (byte) 0xF8,
            (byte) 0x97, (byte) 0x03, (byte) 0xDD, (byte) 0x71, (byte) 0x9A, (byte) 0xBD,
            (byte) 0xC5, (byte) 0x2B, (byte) 0xB1, (byte) 0x8E, (byte) 0x5F, (byte) 0x78,
            (byte) 0x4F, (byte) 0xC3, (byte) 0xE2, (byte) 0xE7, (byte) 0x65, (byte) 0xC0,
            (byte) 0x31, (byte) 0xF8, (byte) 0x97, (byte) 0x03, (byte) 0xDD, (byte) 0x71,
            (byte) 0x9A, (byte) 0xBD, (byte) 0xC5, (byte) 0x2B, (byte) 0xB1};

    private static final byte[] oneByte = {(byte) 0x5F};
    private static byte[] elevenBytes = {(byte) 0x5F, (byte) 0x78, (byte) 0x4F, (byte) 0xC3,
            (byte) 0xE2, (byte) 0xE7, (byte) 0x65, (byte) 0xC0, (byte) 0x31, (byte) 0xF8,
            (byte) 0x97};

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

    // Used by doGenKeyPair method
    final int EMPTY_PARAMS = 0;
    final int DEFAULT_PARAMS = 1;
    final int NONDEFAULT_PARAMS = 2;
    final int PARAMS_SALT40 = 3;

    /**
     * SHA512/224
     * @throws Exception
     */
    @Test
    public void testRSASignatureSHA512_224() throws Exception {


        PSSParameterSpec pssParameter = new PSSParameterSpec("SHA-512", "MGF1",
                MGF1ParameterSpec.SHA512, 64, 1);
        try {
            dotestSignature(content, IBM_ALG, 2048, pssParameter, getProviderName());
        } catch (Exception e) {
            e.printStackTrace();
        }

        // PSSParameterSpec pssParameter2 = new PSSParameterSpec("SHA-512/224", "MGF1",
        //         MGF1ParameterSpec.SHA512_224,28, 1);
        // try {
        //     dotestSignature(content, IBM_ALG, 2048, pssParameter2,
        //             getProviderName());
        // } catch (Exception e) {
        //     e.printStackTrace();
        // }

        PSSParameterSpec pssParameter3 = new PSSParameterSpec("SHA-512/224", "MGF1",
                MGF1ParameterSpec.SHA512_224, 28, 1);
        // PSSParameterSpec pssParameter = new PSSParameterSpec("SHA-512", "MGF1",
        //         MGF1ParameterSpec.SHA512,64, 1);
        try {
            dotestSignature(content, IBM_ALG, 2048, pssParameter3, getProviderName());

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * SHA512/256
     * @throws Exception
     */
    public void testRSASignatureSHA512_256() throws Exception {
        PSSParameterSpec pssParameter = new PSSParameterSpec("SHA512/256", "MGF1",
                MGF1ParameterSpec.SHA512_256,20, 1);
        try {
            dotestSignature(content, IBM_ALG, 2048, pssParameter, getProviderName());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Helper method
     * @param content
     * @param algorithm
     * @param keySize
     * @param pssParameterSpec
     * @param jceprovider
     * @throws Exception
     */
    protected void dotestSignature(byte[] content, String algorithm, int keySize,
            PSSParameterSpec pssParameterSpec, String jceprovider) throws Exception {

        // Generate Signature

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize, new java.security.SecureRandom());
        KeyPair keyPair = keyGen.genKeyPair();

        Signature sig = Signature.getInstance(algorithm, jceprovider);
        if (pssParameterSpec != null) {
            sig.setParameter(pssParameterSpec);
            AlgorithmParameters algParams = sig.getParameters();
            algParams.getParameterSpec(PSSParameterSpec.class);
            //System.out.println("parameters=" + algParams.toString());
        }

        AlgorithmParameters algParams = sig.getParameters();
        algParams.getParameterSpec(PSSParameterSpec.class);
        //System.out.println("parameters=" + algParams.toString());
        sig.initSign(keyPair.getPrivate());
        sig.update(content);
        byte[] sigBytes = sig.sign();

        // Verify the signature
        sig.initVerify(keyPair.getPublic());
        sig.update(content);

        // Check Signature
        // Signature verifySig = Signature.getInstance("SHA1withRSA/PSS",
        // getProviderName());
        // verifySig.initVerify(cert);
        // verifySig.update(content);
        boolean signatureVerified = sig.verify(sigBytes);

        assertTrue("signature is invalid!!", signatureVerified);
    }

}
