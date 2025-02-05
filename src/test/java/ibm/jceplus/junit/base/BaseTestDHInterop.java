/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

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
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestDHInterop extends BaseTestJunit5Interop {


    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    /**
     * Basic ECDH example
     *
     * @throws Exception
     */
    @Test
    public void testDH() throws Exception {

        String idString = ("testDH Keysize:" + Integer.valueOf(getKeySize())).toString();

        DHParameterSpec dhps = generateDHParameters(getKeySize());
        String myInteropProvider = getInteropProviderName();
        String myProvider = getProviderName();

        compute_dh_key_interop(idString, dhps, myProvider, myInteropProvider);
        compute_dh_key_interop(idString, dhps, myInteropProvider, myProvider);
    }

    void compute_dh_key_interop(String idString, AlgorithmParameterSpec algParameterSpec,
            String providerA, String providerB) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        compute_dh_key(idString, algParameterSpec, providerA, providerB);
    }

    void compute_dh_key_interop_sameKeyPairGenerator(String idString,
            AlgorithmParameterSpec algParameterSpec, String providerA, String providerB)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        compute_dh_key_sameKeyPairGenerator(idString, algParameterSpec, providerA, providerB);
    }

    void compute_dh_key(String idString, AlgorithmParameterSpec algParameterSpec, String providerA,
            String providerB) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchProviderException, InvalidKeyException {
        final String methodName = "compute_dh_key" + "_" + idString;

        KeyPairGenerator kpgA = null;
        try {
            kpgA = KeyPairGenerator.getInstance("DH", providerA);
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
            keyAgreeA = KeyAgreement.getInstance("DH", providerA);
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
            kpgB = KeyPairGenerator.getInstance("DH", providerB);
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
        // System.out.println("KeyPairB.privKey=" +
        // BaseUtils.bytesToHex(keyPairB.getPrivate().getEncoded()));
        // System.out.println("KeyPairB.publicKey=" +
        // BaseUtils.bytesToHex(keyPairB.getPublic().getEncoded()));
        // System.out.println("KeyPairA.privKey=" +
        // BaseUtils.bytesToHex(keyPairA.getPrivate().getEncoded()));
        // System.out.println("KeyPairA.publicKey=" +
        // BaseUtils.bytesToHex(keyPairA.getPublic().getEncoded()));

        KeyAgreement keyAgreeB = null;
        try {
            keyAgreeB = KeyAgreement.getInstance("DH", providerB);
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


        boolean assertFlag = Arrays.equals(sharedSecretA, sharedSecretB);
        if (!assertFlag) {
            System.out.println(methodName + " sharedSecretA = "
                    + BaseUtils.bytesToHex(sharedSecretA) + ": " + sharedSecretA.length);
            System.out.println(methodName + " sharedSecretB = "
                    + BaseUtils.bytesToHex(sharedSecretB) + ": " + sharedSecretB.length);

            System.out.println(
                    "KeyPairA.privKey=" + BaseUtils.bytesToHex(keyPairA.getPrivate().getEncoded()));
            System.out.println("KeyPairA.publicKey="
                    + BaseUtils.bytesToHex(keyPairA.getPublic().getEncoded()));

            System.out.println(
                    "KeyPairB.privKey=" + BaseUtils.bytesToHex(keyPairB.getPrivate().getEncoded()));
            System.out.println("KeyPairB.publicKey="
                    + BaseUtils.bytesToHex(keyPairB.getPublic().getEncoded()));

        }
        assertTrue(assertFlag);
    }

    void compute_dh_key_sameKeyPairGenerator(String idString,
            AlgorithmParameterSpec algParameterSpec, String providerA, String providerB)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchProviderException, InvalidKeyException {
        final String methodName = "compute_ecdh_key_sameKeyPairGenerator" + "_" + idString;

        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("DH", providerA);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }

        try {
            kpg.initialize(algParameterSpec);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw e;
        }

        KeyPair keyPairA = kpg.generateKeyPair();

        KeyPair keyPairB = kpg.generateKeyPair();
        // System.out.println("KeyPairA.privKey=" +
        // BaseUtils.bytesToHex(keyPairA.getPrivate().getEncoded()));
        // System.out.println("KeyPairA.publicKey=" +
        // BaseUtils.bytesToHex(keyPairA.getPublic().getEncoded()));

        // set up
        KeyAgreement keyAgreeA = null;
        try {
            keyAgreeA = KeyAgreement.getInstance("DH", providerA);
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

        try {
            keyAgreeA.doPhase(keyPairB.getPublic(), true);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalStateException e) {
            e.printStackTrace();
            throw e;
        }

        // System.out.println("KeyPairB.privKey=" +
        // BaseUtils.bytesToHex(keyPairB.getPrivate().getEncoded()));
        // System.out.println("KeyPairB.publicKey=" +
        // BaseUtils.bytesToHex(keyPairB.getPublic().getEncoded()));

        KeyAgreement keyAgreeB = null;
        try {
            keyAgreeB = KeyAgreement.getInstance("DH", providerB);
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
        boolean assertFlag = Arrays.equals(sharedSecretA, sharedSecretB);
        if (!assertFlag) {
            System.out.println("generated shared secrets are different");
            System.out.println(
                    methodName + " sharedSecretA = " + BaseUtils.bytesToHex(sharedSecretA));
            System.out.println(
                    methodName + " sharedSecretB = " + BaseUtils.bytesToHex(sharedSecretB));

            System.out.println(
                    "KeyPairA.privKey=" + BaseUtils.bytesToHex(keyPairA.getPrivate().getEncoded()));
            System.out.println("KeyPairA.publicKey="
                    + BaseUtils.bytesToHex(keyPairA.getPublic().getEncoded()));

            System.out.println(
                    "KeyPairB.privKey=" + BaseUtils.bytesToHex(keyPairB.getPrivate().getEncoded()));
            System.out.println("KeyPairB.publicKey="
                    + BaseUtils.bytesToHex(keyPairB.getPublic().getEncoded()));
        }
        assertTrue(assertFlag);
    }

    private DHParameterSpec generateDHParameters(int size) throws Exception {
        AlgorithmParameterGenerator algParamGen = AlgorithmParameterGenerator.getInstance("DH",
                getProviderName());
        algParamGen.init(size);
        AlgorithmParameters algParams = algParamGen.generateParameters();
        DHParameterSpec dhps = algParams.getParameterSpec(DHParameterSpec.class);
        return dhps;
    }
}
