/*
 * Copyright IBM Corp. 2023, 2025
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
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import sun.security.pkcs.PKCS8Key;
import sun.security.x509.X509Key;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestECKeyImport extends BaseTestJunit5 {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    // Key encodings to be used in import test.
    private static final String private_secp256r1 = "308193020100301306072A8648CE3D020106082A8648CE"
                                                  + "3D030107047930770201010420CF1AEA9582B330909ED7"
                                                  + "612A6409701E8AF90AC525E3D1CD167FA58A74015455A0"
                                                  + "0A06082A8648CE3D030107A14403420004F5BE5E630BE2"
                                                  + "4DF3E88AAC2B2367E6A546D1D5DEF077F1FD9C8F7F693A"
                                                  + "C665F4DE71F4944327C898680C08E78755D43D88BE501C"
                                                  + "F01EC5C0A07BFA54EFB80C28";
    private static final String public_secp256r1 = "3059301306072A8648CE3D020106082A8648CE3D0301070"
                                                 + "3420004F5BE5E630BE24DF3E88AAC2B2367E6A546D1D5DE"
                                                 + "F077F1FD9C8F7F693AC665F4DE71F4944327C898680C08E"
                                                 + "78755D43D88BE501CF01EC5C0A07BFA54EFB80C28";

    private static final String private_secp384r1 = "3081BF020100301006072A8648CE3D020106052B810400"
                                                  + "220481A73081A4020101043085A782085C553F6A2C3BAA"
                                                  + "0B59ACDF1D90ADFF73CB702EC97A407DFA86716DA4A3C2"
                                                  + "C63238DFE4B514BD3F13C31F6589A00706052B81040022"
                                                  + "A16403620004A71A0D891BFE28D21A5460F8CC8D83D6E8"
                                                  + "35A7114680F645E6906D54ADF97B7B224927E70BAF0776"
                                                  + "855405A640AA48BBD8333CFDD4D2B0EA0E5A8E8122FDDE"
                                                  + "7164A10662067AC4BD00DBB944FC0390E3126FFCD0BE30"
                                                  + "4AC6C1563CEF5FF4ED69";
    private static final String public_secp384r1 = "3076301006072A8648CE3D020106052B810400220362000"
                                                 + "4A71A0D891BFE28D21A5460F8CC8D83D6E835A7114680F6"
                                                 + "45E6906D54ADF97B7B224927E70BAF0776855405A640AA4"
                                                 + "8BBD8333CFDD4D2B0EA0E5A8E8122FDDE7164A10662067A"
                                                 + "C4BD00DBB944FC0390E3126FFCD0BE304AC6C1563CEF5FF"
                                                 + "4ED69";

    private static final String private_secp521r1 = "3081F7020100301006072A8648CE3D020106052B810400"
                                                  + "230481DF3081DC0201010442017A35D78CF723F3603EB5"
                                                  + "F62A9C628C91574062257696E86BB16E7E0AC3A4EA0392"
                                                  + "3932F9DE388B70143C4CEE7F06241EFA8664148E457190"
                                                  + "B8587BAC3A454C83E7A00706052B81040023A181890381"
                                                  + "86000401ABF48EE823860DBE7FEE88F1054C4ED5395EBC"
                                                  + "F1451FD096389FFA95E670B3FC2D18E2E73D7C89E269B0"
                                                  + "16671B26FB1A2013AB2DAB048FE2743D226803795D75C9"
                                                  + "00EF9C57C30FAA2DEF09DDDAD4E8748C442325B8EDB94E"
                                                  + "F7AA978D4A56F0B601448B0DDFA4CC4B0555EAE67354C4"
                                                  + "42A3ACE9D04BE186765A1921962FC08D1A58C53A";
    private static final String public_secp521r1 = "30819B301006072A8648CE3D020106052B8104002303818"
                                                 + "6000401ABF48EE823860DBE7FEE88F1054C4ED5395EBCF1"
                                                 + "451FD096389FFA95E670B3FC2D18E2E73D7C89E269B0166"
                                                 + "71B26FB1A2013AB2DAB048FE2743D226803795D75C900EF"
                                                 + "9C57C30FAA2DEF09DDDAD4E8748C442325B8EDB94EF7AA9"
                                                 + "78D4A56F0B601448B0DDFA4CC4B0555EAE67354C442A3AC"
                                                 + "E9D04BE186765A1921962FC08D1A58C53A";
    

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

    /**
     * Generate a KeyPair, import the key pair through factory and compare the
     * encodings.
     *
     * @throws Exception
     */
    @Test
    public void testCreateKeyPairImportCompareEncodings() throws Exception {

        //final String methodName = "testCreateKeyPairImportCompareEncodings";

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", getProviderName());
        KeyPair keyPair = keyPairGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        byte[] originalPubKeyBytes = publicKey.getEncoded();
        byte[] originalPrivKeyBytes = privateKey.getEncoded();

        KeyFactory keyFactory = KeyFactory.getInstance("EC", getProviderName());
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(originalPrivKeyBytes);
        PrivateKey importPrivateKey = keyFactory.generatePrivate(privateKeySpec);

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(originalPubKeyBytes);
        PublicKey importPublicKey = keyFactory.generatePublic(publicKeySpec);

        byte[] importPubKeyBytes = importPublicKey.getEncoded();
        byte[] importPrivKeyBytes = importPrivateKey.getEncoded();

        // Check that the original and factory created keys produce the same encoding.
        assertArrayEquals(importPubKeyBytes, originalPubKeyBytes, "Public key encodings don't match.");
        assertArrayEquals(importPrivKeyBytes, originalPrivKeyBytes, "Private key encodings don't match.");
    }

    /**
     * Generate a KeyPair, get encoded, import the private key, get the public encoding from it
     * and compare to original public key encoding.
     *
     * @throws Exception
     */
    @Test
    public void testImportHardcoded() throws Exception {

        //final String methodName = "testImportHardcoded";

        KeyFactory keyFactory = KeyFactory.getInstance("EC", getProviderName());

        // Import hard-coded encodings
        // secp256r1
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(HexFormat.of().parseHex(private_secp256r1));
        PrivateKey importPrivateKey = keyFactory.generatePrivate(privateKeySpec);

        assertTrue(((PKCS8Key) importPrivateKey).getAlgorithmId().toString().contains("secp256r1"), "Curve is not what is expected.");

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(HexFormat.of().parseHex(public_secp256r1));
        PublicKey importPublicKey = keyFactory.generatePublic(publicKeySpec);

        assertTrue(((X509Key) importPublicKey).getAlgorithmId().toString().contains("secp256r1"), "Curve is not what is expected.");

        // secp384r1
        privateKeySpec = new PKCS8EncodedKeySpec(HexFormat.of().parseHex(private_secp384r1));
        importPrivateKey = keyFactory.generatePrivate(privateKeySpec);

        assertTrue(((PKCS8Key) importPrivateKey).getAlgorithmId().toString().contains("secp384r1"), "Curve is not what is expected.");

        publicKeySpec = new X509EncodedKeySpec(HexFormat.of().parseHex(public_secp384r1));
        importPublicKey = keyFactory.generatePublic(publicKeySpec);

        assertTrue(((X509Key) importPublicKey).getAlgorithmId().toString().contains("secp384r1"), "Curve is not what is expected.");

        // secp521r1
        privateKeySpec = new PKCS8EncodedKeySpec(HexFormat.of().parseHex(private_secp521r1));
        importPrivateKey = keyFactory.generatePrivate(privateKeySpec);

        assertTrue(((PKCS8Key) importPrivateKey).getAlgorithmId().toString().contains("secp521r1"), "Curve is not what is expected.");

        publicKeySpec = new X509EncodedKeySpec(HexFormat.of().parseHex(public_secp521r1));
        importPublicKey = keyFactory.generatePublic(publicKeySpec);

        assertTrue(((X509Key) importPublicKey).getAlgorithmId().toString().contains("secp521r1"), "Curve is not what is expected.");
    }
}

