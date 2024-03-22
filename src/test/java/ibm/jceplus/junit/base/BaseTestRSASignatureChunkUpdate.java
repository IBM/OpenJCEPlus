/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

public class BaseTestRSASignatureChunkUpdate extends BaseTestSignature {
    static final String KEY_ALGO = "RSA";
    static final int KEY_SIZE = 2048;

    protected KeyPairGenerator keyPairGenerator = null;
    protected KeyPair keyPair = null;
    protected int specifiedKeySize = 0;

    public BaseTestRSASignatureChunkUpdate(String providerName) {
        super(providerName);
    }

    public void setUp() throws Exception {
        keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGO, providerName);
        if (specifiedKeySize > 0) {
            keyPairGenerator.initialize(specifiedKeySize);
        } else {
            keyPairGenerator.initialize(KEY_SIZE);
        }
        keyPair = keyPairGenerator.generateKeyPair();
    }

    public void tearDown() throws Exception {}

    public void testSignatureChunks() throws Exception {
        try {
            testSignatureChunkUpdate(1024, "SHA1WithRSA", 100);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.contains("FIPS")) {
                assertEquals("no such algorithm: SHA1WithRSA for provider OpenJCEPlusFIPS", nsae.getMessage());
            } else {
                throw nsae;
            }
        }
        
        testSignatureChunkUpdate(1024, "SHA256WithRSA", 100);
        
        try {
            testSignatureChunkUpdate2(1024, "SHA1WithRSA", 100);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.contains("FIPS")) {
                assertEquals("no such algorithm: SHA1WithRSA for provider OpenJCEPlusFIPS", nsae.getMessage());
            } else {
                throw nsae;
            }
        }
    }

    private void testSignatureChunkUpdate(int inputSize, String sigAlgo, int chunkSize)
            throws Exception {
        System.out.println("Algorithm: " + sigAlgo + " - Input Size: " + inputSize
                + " - Chunk Size: " + chunkSize);
        byte[] inputBytes = getString(inputSize).getBytes();
        Signature signSignature;

        if (providerName.contains("FIPS") && sigAlgo.contains("SHA1")) {
            System.out.println("Sign with " + sigAlgo + ", provider: OpenJCEPlus");
            signSignature = Signature.getInstance(sigAlgo, "OpenJCEPlus");
        } else {
            System.out.println("Sign with " + sigAlgo + ", provider: " + providerName);
            signSignature = Signature.getInstance(sigAlgo, providerName);
        }

        // Sign the message
        signSignature.initSign(keyPair.getPrivate());
        int i = 0;
        for (i = 0; i < (inputBytes.length / chunkSize); i++) {
            signSignature.update(inputBytes, i * chunkSize, chunkSize);
            System.out.println(
                    "Sign Update - Offset: " + (i * chunkSize) + " - Length: " + chunkSize);
        }
        if (inputBytes.length % chunkSize != 0) {
            signSignature.update(inputBytes, i * chunkSize, (inputBytes.length % chunkSize));
            System.out.println("Sign Update - Offset: " + (i * chunkSize) + " - Length: "
                    + (inputBytes.length % chunkSize));
        }
        byte[] sigBytes = signSignature.sign();
        System.out.println("Signature Bytes Length: " + sigBytes.length);

        // Verify the signature
        System.out.println("Verify with " + sigAlgo + ", provider: " + providerName);
        Signature verifySignature = Signature.getInstance(sigAlgo, providerName);
        verifySignature.initVerify(keyPair.getPublic());
        for (i = 0; i < (inputBytes.length / chunkSize); i++) {
            verifySignature.update(inputBytes, i * chunkSize, chunkSize);
            System.out.println(
                    "Verify Update - Offset: " + (i * chunkSize) + " - Length: " + chunkSize);
        }
        if (inputBytes.length % chunkSize != 0) {
            verifySignature.update(inputBytes, i * chunkSize, (inputBytes.length % chunkSize));
            System.out.println("Verify Update - Offset: " + (i * chunkSize) + " - Length: "
                    + (inputBytes.length % chunkSize));
        }

        boolean result = verifySignature.verify(sigBytes);

        System.out.println("Result(should be true): " + result);

        assertTrue(result);
    }

    // Test signing with SHA1WithRSA for OpenJCEPlusFIPS => this should fail
    private void testSignatureChunkUpdate2(int inputSize, String sigAlgo, int chunkSize)
            throws Exception {
        System.out.println("Algorithm: " + sigAlgo + " - Input Size: " + inputSize
                + " - Chunk Size: " + chunkSize);
        byte[] inputBytes = getString(inputSize).getBytes();
        boolean result = false;

        try {
            Signature signSignature = Signature.getInstance(sigAlgo, providerName);

            // Sign the message
            System.out.println("Sign with " + sigAlgo + ", provider: " + providerName);
            signSignature.initSign(keyPair.getPrivate());
            int i = 0;
            for (i = 0; i < (inputBytes.length / chunkSize); i++) {
                signSignature.update(inputBytes, i * chunkSize, chunkSize);
                System.out.println(
                        "Sign Update - Offset: " + (i * chunkSize) + " - Length: " + chunkSize);
            }
            if (inputBytes.length % chunkSize != 0) {
                signSignature.update(inputBytes, i * chunkSize, (inputBytes.length % chunkSize));
                System.out.println("Sign Update - Offset: " + (i * chunkSize) + " - Length: "
                        + (inputBytes.length % chunkSize));
            }
            byte[] sigBytes = signSignature.sign();
            System.out.println("Signature Bytes Length: " + sigBytes.length);

            // Verify the signature
            System.out.println("Verify with " + sigAlgo + ", provider: " + providerName);
            Signature verifySignature = Signature.getInstance(sigAlgo, providerName);
            verifySignature.initVerify(keyPair.getPublic());
            for (i = 0; i < (inputBytes.length / chunkSize); i++) {
                verifySignature.update(inputBytes, i * chunkSize, chunkSize);
                System.out.println(
                        "Verify Update - Offset: " + (i * chunkSize) + " - Length: " + chunkSize);
            }
            if (inputBytes.length % chunkSize != 0) {
                verifySignature.update(inputBytes, i * chunkSize, (inputBytes.length % chunkSize));
                System.out.println("Verify Update - Offset: " + (i * chunkSize) + " - Length: "
                        + (inputBytes.length % chunkSize));
            }

            result = verifySignature.verify(sigBytes);

        } catch (SignatureException ex) {
            if (providerName.contains("FIPS") && sigAlgo.contains("SHA1")) {
                System.out.print("Could not sign data, " + "Provider: " + providerName
                        + ", Algorithm: " + sigAlgo + " <== Expected SignatureException caught\n");
                System.out.println("Result(should be false): " + result);
                assertFalse(result);
                return;
            } else {
                ex.printStackTrace();
                throw new SignatureException("Could not sign data");
            }
        }

        System.out.println("Result(should be true): " + result);
        assertTrue(result);
    }

    private String getString(int size) {
        String s = "";
        for (int i = 0; i < size; i++) {
            s += "a";
        }
        return s;
    }
}
