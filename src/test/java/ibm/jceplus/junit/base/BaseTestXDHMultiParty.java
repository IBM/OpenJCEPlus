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
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestXDHMultiParty extends BaseTestJunit5 {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    @Test
    public void testXDHMulti_x25519() throws Exception {

        String curveName = "X25519";

        NamedParameterSpec nps = new NamedParameterSpec(curveName);

        try {
            compute_xdh_multiparty_oneprovider(curveName, nps, getProviderName());
        } catch (IllegalStateException e) {
            assertTrue(true);
            return;
        }
        assertTrue(false);
    }

    @Test
    public void testXDHMulti_x448() throws Exception {

        String curveName = "X448";

        NamedParameterSpec nps = new NamedParameterSpec(curveName);

        try {
            compute_xdh_multiparty_oneprovider(curveName, nps, getProviderName());
        } catch (IllegalStateException e) {
            assertTrue(true);
            return;
        }
        assertTrue(false);
    }

    @Test
    public void testXDHMulti_ffdhe2048() throws Exception {

        String curveName = "FFDHE2048";

        NamedParameterSpec nps = new NamedParameterSpec(curveName);

        try {
            compute_xdh_multiparty_oneprovider(curveName, nps, getProviderName());
        } catch (IllegalStateException e) {
            assertTrue(true);
            return;
        }
        assertTrue(false);
    }

    @Test
    public void testXDHMulti_ffdhe3072() throws Exception {

        String curveName = "FFDHE3072";

        NamedParameterSpec nps = new NamedParameterSpec(curveName);

        try {
            compute_xdh_multiparty_oneprovider(curveName, nps, getProviderName());
        } catch (IllegalStateException e) {
            assertTrue(true);
            return;
        }
        assertTrue(false);
    }

    @Test
    public void testXDHMulti_ffdhe4096() throws Exception {

        String curveName = "FFDHE4096";

        NamedParameterSpec nps = new NamedParameterSpec(curveName);

        try {
            compute_xdh_multiparty_oneprovider(curveName, nps, getProviderName());
        } catch (IllegalStateException e) {
            assertTrue(true);
            return;
        }
        assertTrue(false);
    }

    @Test
    public void testXDHMulti_ffdhe6144() throws Exception {

        String curveName = "FFDHE6144";

        NamedParameterSpec nps = new NamedParameterSpec(curveName);

        try {
            compute_xdh_multiparty_oneprovider(curveName, nps, getProviderName());
        } catch (IllegalStateException e) {
            assertTrue(true);
            return;
        }
        assertTrue(false);
    }

    @Test
    public void testXDHMulti_ffdhe8192() throws Exception {

        String curveName = "FFDHE8192";

        NamedParameterSpec nps = new NamedParameterSpec(curveName);

        try {
            compute_xdh_multiparty_oneprovider(curveName, nps, getProviderName());
        } catch (IllegalStateException e) {
            //System.out.println(e.getMessage());
            assertTrue(true);
            return;
        }
        assertTrue(false);
    }

    void compute_xdh_multiparty_oneprovider(String idString,
            AlgorithmParameterSpec algParameterSpec, String provider)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchProviderException, InvalidKeyException {
        //final String methodName = "compute_xdh_multiparty" + "_" + idString;

        KeyPairGenerator kpgA = null;
        KeyPairGenerator kpgB = null;
        KeyPairGenerator kpgC = null;
        try {
            kpgA = KeyPairGenerator.getInstance("XDH", provider);
            kpgB = KeyPairGenerator.getInstance("XDH", provider);
            kpgC = KeyPairGenerator.getInstance("XDH", provider);
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
            keyAgreeA = KeyAgreement.getInstance("XDH", provider);
            keyAgreeB = KeyAgreement.getInstance("XDH", provider);
            keyAgreeC = KeyAgreement.getInstance("XDH", provider);
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
