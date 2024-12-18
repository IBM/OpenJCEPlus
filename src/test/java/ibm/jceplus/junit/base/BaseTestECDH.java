/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.crypto.KeyAgreement;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestECDH extends BaseTestJunit5 {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();
    static ECGenParameterSpec algParameterSpec_192k1, algParameterSpec_256r1;

    static KeyPairGenerator kpgA = null;
    static KeyPairGenerator kpgB = null;

    static KeyPair keyPairA_192k1, keyPairA_256r1;
    static KeyPair keyPairB_192k1, keyPairB_256r1;

    private boolean isMulti = false;

    static boolean generated = false;

    public boolean isMulti() {
        return isMulti;
    }

    public void setMulti(boolean isMulti) {
        this.isMulti = isMulti;
    }

    synchronized static void generateParams(String provider_name) {
        if (generated)
            return;
        try {

            //String provider_name = "OpenJCEPlus";
            String curveName_192k1 = "secp192k1";
            String curveName_256r1 = "secp256r1";

            algParameterSpec_192k1 = new ECGenParameterSpec(curveName_192k1);
            algParameterSpec_256r1 = new ECGenParameterSpec(curveName_256r1);

            kpgA = KeyPairGenerator.getInstance("EC", provider_name);
            kpgA.initialize(algParameterSpec_192k1);
            keyPairA_192k1 = kpgA.generateKeyPair();
            kpgA.initialize(algParameterSpec_256r1);
            keyPairA_256r1 = kpgA.generateKeyPair();

            kpgB = KeyPairGenerator.getInstance("EC", provider_name);
            kpgB.initialize(algParameterSpec_192k1);
            keyPairB_192k1 = kpgB.generateKeyPair();
            kpgB.initialize(algParameterSpec_256r1);
            keyPairB_256r1 = kpgB.generateKeyPair();

            generated = true;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    @BeforeEach
    public void setUp() {
        generateParams(getProviderName());
    }

    /**
     * Basic ECDH example
     *
     * @throws Exception
     */
    @Test
    public void testECDH_secp192k1() throws Exception {

        String curveName = "secp192k1";

        ECGenParameterSpec ecgn = new ECGenParameterSpec(curveName);

        compute_ecdh_key(curveName, ecgn);
        if (isMulti)
            compute_ecdh_key_with_global_key(curveName, algParameterSpec_192k1);

    }

    @Test
    public void testECDH_secp256r1() throws Exception {

        String curveName = "secp256r1";

        ECGenParameterSpec ecgn = new ECGenParameterSpec(curveName);

        compute_ecdh_key(curveName, ecgn);
        if (isMulti)
            compute_ecdh_key_with_global_key(curveName, algParameterSpec_256r1);

    }

    @Test
    public void testECDH_ECSpec() throws Exception {

        String methodId = "ECDHECParamSpec";

        // These values were copied from ECNamedCurve.java in IBMJCEFIPS
        String sfield_p256 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
        String sa_p256 = "0000000000000000000000000000000000000000000000000000000000000000";
        String sb_p256 = "0000000000000000000000000000000000000000000000000000000000000007";
        String sx_p256 = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        String sy_p256 = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
        String sorder_p256 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

        BigInteger p = new BigInteger(sfield_p256, 16);
        ECField field = new ECFieldFp(p);

        EllipticCurve curve = new EllipticCurve(field, new BigInteger(sa_p256, 16),
                new BigInteger(sb_p256, 16));
        ECPoint g = new ECPoint(new BigInteger(sx_p256, 16), new BigInteger(sy_p256, 16));
        BigInteger order = new BigInteger(sorder_p256, 16);

        int cofactor = 1;
        ECParameterSpec ecParamSpec = new ECParameterSpec(curve, g, order, cofactor);

        compute_ecdh_key(methodId, ecParamSpec);

    }

    void compute_ecdh_key(String idString, AlgorithmParameterSpec algParameterSpec)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchProviderException, InvalidKeyException {
        //final String methodName = "compute_ecdh_key" + "_" + idString;

        KeyPairGenerator kpgA = null;
        try {
            kpgA = KeyPairGenerator.getInstance("EC", getProviderName());
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
        //        System.out.println("KeyPairA.privKey=" + BaseUtils.bytesToHex(keyPairA.getPrivate().getEncoded()));
        //        System.out.println("KeyPairA.publicKey=" + BaseUtils.bytesToHex(keyPairA.getPublic().getEncoded()));

        // set up
        KeyAgreement keyAgreeA = null;
        try {
            keyAgreeA = KeyAgreement.getInstance("ECDH", getProviderName());
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
            kpgB = KeyPairGenerator.getInstance("EC", getProviderName());
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
        //        System.out.println("KeyPairB.privKey=" + BaseUtils.bytesToHex(keyPairB.getPrivate().getEncoded()));
        //        System.out.println("KeyPairB.publicKey=" + BaseUtils.bytesToHex(keyPairB.getPublic().getEncoded()));

        KeyAgreement keyAgreeB = null;
        try {
            keyAgreeB = KeyAgreement.getInstance("ECDH", getProviderName());
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
        //        System.out.println(methodName + " sharedSecretA = " + BaseUtils.bytesToHex(sharedSecretA));
        //        System.out.println(methodName + " sharedSecretB = " + BaseUtils.bytesToHex(sharedSecretB));

        assertTrue(Arrays.equals(sharedSecretA, sharedSecretB));

    }

    /*
     * Ensure InvalidParameterSpecException is thrown by ECParamaters init method when given an 
     * unrecognized curve name.
     * Was throwing an InvalidParameterException from ECNamedCurve constructor taking single String argument
     */
    @Test
    public void testEC_engineInit_AlgorithmParameterSpec_paramSpec() throws Exception {
        String curveName = "UnknownCurveNameShouldGenerateInvalidParameterSpecException";

        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC",
                getProviderName());
        assertNotNull(algorithmParameters, "AlgorithmParameters EC not found in provider" + getProviderName());

        AlgorithmParameterSpec algorithmParameterSpec = new ECGenParameterSpec(curveName);

        try {
            algorithmParameters.init(algorithmParameterSpec);
        } catch (InvalidParameterSpecException ipe) {
            // check the message to make sure this comes from ECNamedCurve constructor
            String exmsg = "Not a supported curve";
            assertTrue(ipe.getMessage().contains(exmsg));
            return; //correct exception type AND exception message so pass the test
        } catch (Throwable throwable) {
            fail("InvalidParameterSpecException expected but caught: " + throwable);
        }

        fail("InvalidParameterSpecException expected but no exception was thrown");
    }

    void compute_ecdh_key_with_global_key(String idString, AlgorithmParameterSpec algParameterSpec)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchProviderException, InvalidKeyException {
        final String methodName = "compute_ecdh_key_with_global_key" + "_" + idString;
        KeyPair keyPairA = null, keyPairB = null;
        switch (idString) {
            case "secp192k1":
                keyPairA = keyPairA_192k1;
                keyPairB = keyPairB_192k1;
                break;

            case "secp256r1":
                keyPairA = keyPairA_256r1;
                keyPairB = keyPairB_256r1;
                break;
        }

        // set up
        KeyAgreement keyAgreeA = null;
        try {
            keyAgreeA = KeyAgreement.getInstance("ECDH", getProviderName());
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

        KeyAgreement keyAgreeB = null;
        try {
            keyAgreeB = KeyAgreement.getInstance("ECDH", getProviderName());
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
        System.out.println(methodName + " sharedSecretB = " + BaseUtils.bytesToHex(sharedSecretB));
        assertTrue(Arrays.equals(sharedSecretA, sharedSecretB));
    }

}

