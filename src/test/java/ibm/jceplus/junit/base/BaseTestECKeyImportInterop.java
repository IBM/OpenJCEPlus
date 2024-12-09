/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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
import static org.junit.Assert.assertTrue;

public class BaseTestECKeyImportInterop extends BaseTestJunit5Interop {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    @Test
    public void testCreateKeyPairECGenParamImport() throws Exception {
        doCreateKeyPairECGenParamImport(getProviderName(), getInteropProviderName());
        doCreateKeyPairECGenParamImport(getInteropProviderName(), getProviderName());
    }

    public void doCreateKeyPairECGenParamImport(String generateProviderName,
            String importProviderName) throws Exception {

        //final String methodName = "doCreateKeyPairECGenParamImport";

        ECGenParameterSpec ecgn = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", generateProviderName);

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

        KeyFactory keyFactory = KeyFactory.getInstance("EC", importProviderName);
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);
        PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubKeyBytes);
        PublicKey publicKey2 = keyFactory.generatePublic(publicKeySpec);

        // The original and new keys are the same
        assertTrue(Arrays.equals(publicKey2.getEncoded(), pubKeyBytes));
        assertTrue(Arrays.equals(privateKey2.getEncoded(), privKeyBytes));
    }

    @Test
    public void testCreateKeyPairECParamCustomCurveImport() throws Exception {
        doCreateKeyPairECParamCustomCurveImport(getProviderName(), getInteropProviderName());
        if (System.getProperty("os.name").equals("z/OS")) {
            System.out.println(
                    "SunEC doesn't have the necessary EC algorithms, test BaseTestECKeyImportInterop.testCreateKeyPairECParamCustomCurveImport() skipped.");
            return;
        }
        doCreateKeyPairECParamCustomCurveImport(getInteropProviderName(), getProviderName());
    }

    public void doCreateKeyPairECParamCustomCurveImport(String createProviderName,
            String importProviderName) throws Exception {

        //final String methodName = "doCreateKeyPairECParamImport";

        // These values were copied from CurveDB.java in OpenJDK for secp521r1
        String sfield_p521 = "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        String sa_p521 = "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC";
        String sb_p521 = "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00";
        String sx_p521 = "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66";
        String sy_p521 = "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650";
        String sorder_p521 = "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409";

        BigInteger p = new BigInteger(sfield_p521, 16);
        ECField field = new ECFieldFp(p);

        EllipticCurve curve = new EllipticCurve(field, new BigInteger(sa_p521, 16),
                new BigInteger(sb_p521, 16));
        ECPoint g = new ECPoint(new BigInteger(sx_p521, 16), new BigInteger(sy_p521, 16));
        BigInteger order = new BigInteger(sorder_p521, 16);

        int cofactor = 1;

        ECParameterSpec ecParamSpec = new ECParameterSpec(curve, g, order, cofactor);

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", createProviderName);
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

        KeyFactory keyFactory = KeyFactory.getInstance("EC", importProviderName);
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);
        PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey2 = keyFactory.generatePublic(publicKeySpec);

        byte[] publicKey2Bytes = publicKey2.getEncoded();
        byte[] privateKey2Bytes = privateKey2.getEncoded();

        assertTrue(Arrays.equals(publicKey2Bytes, publicKeyBytes));
        assertTrue(Arrays.equals(privateKey2Bytes, privKeyBytes));
    }
}
