/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import org.junit.jupiter.api.Test;
import static org.junit.Assert.assertTrue;

public class BaseTestDHMultiParty extends BaseTestJunit5 {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    /**
     * Basic DH example
     *
     * @throws Exception
     */
    @Test
    public void testDHMulti() throws Exception {

        String id = "testDHMulti";

        BigInteger p_2048 = new BigInteger(
                "24411209893452987982292764298214666563244502108061332429386640762028613944128160958895651358369340617913723942648980595662900397364654037992477306346975555070731906211991330607572500092846972550669206248817906971178489109618091786420639402573006669894740449806296627656350692199924647254064170619723090086490863047112010159257790253286951285397621794370492477371659895119712649029073020971899481274886979229883486313718228936740160705239157339084673807557507596909526771665732158004755500890957481963807104507454286192846294557895603003106614304345189884618591002156946923803100585097553740787441936978505629483919483");


        BigInteger g_2048 = new BigInteger("2");

        DHParameterSpec dhParams = new DHParameterSpec(p_2048, g_2048);

        try {
            compute_dh_multiparty(id, dhParams, getProviderName());
        } catch (IllegalStateException e) {
            //System.out.println(e.getMessage());
            assertTrue(true);
        }
    }

    void compute_dh_multiparty(String idString, DHParameterSpec dhParameterSpec, String provider)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchProviderException, InvalidKeyException {
        //final String methodName = "compute_dh_multiparty" + "_" + idString;

        KeyPairGenerator kpgA = null;
        KeyPairGenerator kpgB = null;
        KeyPairGenerator kpgC = null;
        try {
            kpgA = KeyPairGenerator.getInstance("DH", provider);
            kpgB = KeyPairGenerator.getInstance("DH", provider);
            kpgC = KeyPairGenerator.getInstance("DH", provider);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }

        try {
            kpgA.initialize(dhParameterSpec);
            kpgB.initialize(dhParameterSpec);
            kpgC.initialize(dhParameterSpec);

        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw e;
        }

        KeyPair keyPairA = kpgA.generateKeyPair();
        KeyPair keyPairB = kpgB.generateKeyPair();
        KeyPair keyPairC = kpgC.generateKeyPair();

        // System.out.println("KeyPairA.privKey=" +
        // BaseUtils.bytesToHex(keyPairA.getPrivate().getEncoded()));
        // System.out.println("KeyPairA.publicKey=" +
        // BaseUtils.bytesToHex(keyPairA.getPublic().getEncoded()));

        // set up
        KeyAgreement keyAgreeA = null;
        KeyAgreement keyAgreeB = null;
        KeyAgreement keyAgreeC = null;
        try {
            keyAgreeA = KeyAgreement.getInstance("DH", provider);
            keyAgreeB = KeyAgreement.getInstance("DH", provider);
            keyAgreeC = KeyAgreement.getInstance("DH", provider);
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
        //        System.out.println(methodName + " sharedSecretA = " + BaseUtils.bytesToHex(sharedSecretA));
        //        System.out.println(methodName + " sharedSecretB = " + BaseUtils.bytesToHex(sharedSecretB));
        //        System.out.println(methodName + " sharedSecretC = " + BaseUtils.bytesToHex(sharedSecretC));

        assertTrue(Arrays.equals(sharedSecretA, sharedSecretB));
        assertTrue(Arrays.equals(sharedSecretA, sharedSecretC));
        assertTrue(Arrays.equals(sharedSecretB, sharedSecretC));

    }
}
