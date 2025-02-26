/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestECDHMultiParty extends BaseTestJunit5 {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    /**
     * Basic ECDH example
     *
     * @throws Exception
     */
    @Test
    public void testECDHMulti_secp192k1() throws Exception {

        String curveName = "secp192k1";

        ECGenParameterSpec ecgn = new ECGenParameterSpec(curveName);

        try {
            compute_ecdh_multiparty_oneprovider(curveName, ecgn, getProviderName());
        } catch (IllegalStateException e) {
            //System.out.println(e.getMessage());
            assertTrue(true);
        }
    }

    void compute_ecdh_multiparty_oneprovider(String idString,
            AlgorithmParameterSpec algParameterSpec, String provider)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchProviderException, InvalidKeyException {
        //final String methodName = "compute_ecdh_multiparty" + "_" + idString;

        KeyPairGenerator kpgA = null;
        KeyPairGenerator kpgB = null;
        KeyPairGenerator kpgC = null;
        try {
            kpgA = KeyPairGenerator.getInstance("EC", provider);
            kpgB = KeyPairGenerator.getInstance("EC", provider);
            kpgC = KeyPairGenerator.getInstance("EC", provider);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }

        try {
            kpgA.initialize(algParameterSpec);
            kpgB.initialize(algParameterSpec);
            kpgC.initialize(algParameterSpec);

        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw e;
        }

        KeyPair keyPairA = kpgA.generateKeyPair();
        KeyPair keyPairB = kpgB.generateKeyPair();
        KeyPair keyPairC = kpgC.generateKeyPair();

        // System.out.println("KeyPairA.privKey=" +
        // .BaseUtils.bytesToHex(keyPairA.getPrivate().getEncoded()));
        // System.out.println("KeyPairA.publicKey=" +
        // BaseUtils.bytesToHex(keyPairA.getPublic().getEncoded()));

        // set up
        KeyAgreement keyAgreeA = null;
        KeyAgreement keyAgreeB = null;
        KeyAgreement keyAgreeC = null;
        try {
            keyAgreeA = KeyAgreement.getInstance("ECDH", provider);
            keyAgreeB = KeyAgreement.getInstance("ECDH", provider);
            keyAgreeC = KeyAgreement.getInstance("ECDH", provider);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }

        try {
            keyAgreeA.init(keyPairA.getPrivate());
            keyAgreeB.init(keyPairB.getPrivate());
            keyAgreeC.init(keyPairC.getPrivate());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw e;
        }

        // Multiparty agreement

        Key ac = null;
        Key ba = null;
        Key cb = null;
        try {
            ac = keyAgreeA.doPhase(keyPairC.getPublic(), false);
            ba = keyAgreeB.doPhase(keyPairA.getPublic(), false);
            cb = keyAgreeC.doPhase(keyPairB.getPublic(), false);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw e;
        } catch (IllegalStateException e) {
            //e.printStackTrace();
            throw e;
        }

        // do the last phase
        keyAgreeA.doPhase(cb, true);
        keyAgreeB.doPhase(ac, true);
        keyAgreeC.doPhase(ba, true);

        // Generate the key bytes
        byte[] sharedSecretA = keyAgreeA.generateSecret();
        byte[] sharedSecretB = keyAgreeB.generateSecret();
        byte[] sharedSecretC = keyAgreeC.generateSecret();
        //System.out.println(methodName + " sharedSecretA = " + BaseUtils.bytesToHex(sharedSecretA));
        //System.out.println(methodName + " sharedSecretB = " + BaseUtils.bytesToHex(sharedSecretB));
        //System.out.println(methodName + " sharedSecretC = " + BaseUtils.bytesToHex(sharedSecretC));

        assertTrue(Arrays.equals(sharedSecretA, sharedSecretB));
        assertTrue(Arrays.equals(sharedSecretA, sharedSecretC));
        assertTrue(Arrays.equals(sharedSecretB, sharedSecretC));

    }
}
