/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestECKeyImport extends BaseTestJunit5 {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    /**
     * Generate a KeyPair using ECGEenParam and then import the key pair
     *
     * @throws Exception
     */
    @Test
    public void testCreateKeyPairECGenParamImport() throws Exception {

        //final String methodName = "testCreateKeyPairECGenParamImport";

        ECGenParameterSpec ecgn = new ECGenParameterSpec("secp192k1");
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", getProviderName());

        keyPairGen.initialize(ecgn);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        byte[] pubKeyBytes = publicKey.getEncoded();
        byte[] privKeyBytes = privateKey.getEncoded();

        // Uncomment and run asn1dec.exe
        // System.out.println (methodName + " pubKeyBytes length=" +
        // pubKeyBytes.length);
        // System.out.println (methodName + " publicKeyBytes = " +
        // BaseUtils.bytesToHex(pubKeyBytes));
        // System.out.println (methodName + " privKeyBytes length=" +
        // privKeyBytes.length);
        // System.out.println (methodName + " privKeyBytes = " +
        // BaseUtils.bytesToHex(privKeyBytes));

        KeyFactory keyFactory = KeyFactory.getInstance("EC", getProviderName());
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);
        PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubKeyBytes);
        PublicKey publicKey2 = keyFactory.generatePublic(publicKeySpec);

        // The original and new keys are the same
        boolean same = privateKey.equals(privateKey2);
        assertTrue(same);
        same = publicKey.equals(publicKey2);
        assertTrue(same);
    }

    /**
     *
     * @throws Exception
     *             During the encoding, the provider should recognize that this is
     *             same as a Known curve and encodes only the OID for named Curve
     */
    @Test
    public void testCreateKeyPairECParamImport() throws Exception {

        //final String methodName = "testCreateKeyPairECParamImport";

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
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", getProviderName());

        keyPairGen.initialize(ecParamSpec);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        byte[] publicKeyBytes = publicKey.getEncoded();
        byte[] privKeyBytes = privateKey.getEncoded();

        // System.out.println (methodName + " pubKeyBytes length=" +
        // publicKeyBytes.length);
        // System.out.println (methodName + " publicKeyBytes = " +
        // BaseUtils.bytesToHex(publicKeyBytes));
        // System.out.println (methodName + " privKeyBytes length=" +
        // privKeyBytes.length);
        // System.out.println (methodName + " privKeyBytes = " +
        // BaseUtils.bytesToHex(privKeyBytes));

        KeyFactory keyFactory = KeyFactory.getInstance("EC", getProviderName());
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);
        PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey2 = keyFactory.generatePublic(publicKeySpec);

        // The original and new keys are the same
        boolean same = privateKey.equals(privateKey2);
        assertTrue(same);
        same = publicKey.equals(publicKey2);
        assertTrue(same);
        byte[] publicKey2Bytes = publicKey2.getEncoded();
        byte[] privateKey2Bytes = privateKey2.getEncoded();

        assertTrue(Arrays.equals(publicKey2Bytes, publicKeyBytes));
        assertTrue(Arrays.equals(privateKey2Bytes, privKeyBytes));
    }
}

