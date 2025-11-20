/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestECDHInterop extends BaseTestJunit5Interop {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    /**
     * Basic ECDH example
     *
     * @throws Exception
     */
    @Disabled("Curve secp192k1 removed via https://bugs.openjdk.org/browse/JDK-8251547 in JDK16")
    public void ignore_testECDH_secp192k1() throws Exception {

        String curveName = "secp192k1";

        ECGenParameterSpec ecgn = new ECGenParameterSpec(curveName);

        compute_ecdh_key_interop(curveName, ecgn, getProviderName(), getInteropProviderName());
        compute_ecdh_key_interop(curveName, ecgn, getInteropProviderName(), getProviderName());

        compute_ecdh_key_interop_sameKeyPairGenerator(curveName, ecgn, getProviderName(),
                getInteropProviderName());
        compute_ecdh_key_interop_sameKeyPairGenerator(curveName, ecgn, getInteropProviderName(),
                getProviderName());

    }

    @Test
    public void testECDH_encdoing() throws Exception {
        test_ecdh_keyFactory(getProviderName(), getProviderName());
        test_ecdh_keyFactory(getInteropProviderName(), getInteropProviderName());
        test_ecdh_keyFactory(getProviderName(), getInteropProviderName());
        test_ecdh_keyFactory(getInteropProviderName(), getProviderName());
    }

    @Test
    public void testECDH_secp256r1() throws Exception {

        String curveName = "secp256r1";

        ECGenParameterSpec ecgn = new ECGenParameterSpec(curveName);

        compute_ecdh_key_interop(curveName, ecgn, getProviderName(), getInteropProviderName());
        compute_ecdh_key_interop(curveName, ecgn, getInteropProviderName(), getProviderName());

        compute_ecdh_key_interop_sameKeyPairGenerator(curveName, ecgn, getProviderName(),
                getInteropProviderName());
        compute_ecdh_key_interop_sameKeyPairGenerator(curveName, ecgn, getInteropProviderName(),
                getProviderName());

    }

    @Disabled("Curve secp256k1 removed via https://bugs.openjdk.org/browse/JDK-8251547 in JDK16")
    public void ignore_testECDH_ECSpec() throws Exception {
        if (System.getProperty("os.name").equals("z/OS")) {
            System.out.println(
                    "SunEC doesn't have the necessary EC algorithms, test BaseTestECDHInterop.testECDH_ECSpec() skipped.");
            return;
        }
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

        compute_ecdh_key_interop(methodId, ecParamSpec, getProviderName(), getInteropProviderName());
        compute_ecdh_key_interop(methodId, ecParamSpec, getInteropProviderName(), getProviderName());

        compute_ecdh_key_interop_sameKeyPairGenerator(methodId, ecParamSpec, getProviderName(),
                getInteropProviderName());
        compute_ecdh_key_interop_sameKeyPairGenerator(methodId, ecParamSpec, getInteropProviderName(),
                getProviderName());

    }

    void compute_ecdh_key_interop(String curveName, AlgorithmParameterSpec algParameterSpec,
            String providerA, String providerB) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        compute_ecdh_key(curveName, algParameterSpec, providerA, providerB);

    }

    void compute_ecdh_key_interop_sameKeyPairGenerator(String curveName,
            AlgorithmParameterSpec algParameterSpec, String providerA, String providerB)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        compute_ecdh_key_sameKeyPairGenerator(curveName, algParameterSpec, providerA, providerB);

    }

    void compute_ecdh_key(String idString, AlgorithmParameterSpec algParameterSpec,
            String providerA, String providerB) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeyException {
        //final String methodName = "compute_ecdh_key" + "_" + idString;

        KeyPairGenerator kpgA = null;
        try {
            kpgA = KeyPairGenerator.getInstance("EC", providerA);
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
            keyAgreeA = KeyAgreement.getInstance("ECDH", providerA);
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
            kpgB = KeyPairGenerator.getInstance("EC", providerB);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }

        try {
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
            keyAgreeB = KeyAgreement.getInstance("ECDH", providerB);
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

    void test_ecdh_keyFactory(String providerNameX, String providerNameY) throws Exception {
        /*
         * A creates own DH key pair with 2048-bit key size
         */
        //final String methodName = "test_ecdh_keyFactory ";
        System.out.println("A: Generate EC keypair ...");
        KeyPairGenerator aKpairGen = KeyPairGenerator.getInstance("EC", providerNameX);
        aKpairGen.initialize(256);
        KeyPair aKpair = aKpairGen.generateKeyPair();

        // A creates and initializes A DH KeyAgreement object
        // System.out.println("A: Initialization ...");
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", providerNameX);
        aKeyAgree.init(aKpair.getPrivate());
        // System.out.println ("A's publicKey as created by A=" +
        // aKpair.getPublic().toString());

        // A encodes A's public key, and sends it over to B.
        byte[] aPubKeyEnc = aKpair.getPublic().getEncoded();
        // System.out.println ("A's publicKey in HEx as created by A=" +
        // toHexString(aPubKeyEnc));

        /*
         * Let's turn over to B. B has received A's public key in encoded format. B
         * instantiates a DH public key from the encoded key material.
         */
        KeyFactory bKeyFac = KeyFactory.getInstance("EC", providerNameY);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(aPubKeyEnc);

        PublicKey aPubKey = bKeyFac.generatePublic(x509KeySpec);
        // System.out.println ("A's publicKey as recreated by B=" + aPubKey.toString());

        /*
         * B gets the DH parameters associated with A's public key.B must use the same
         * parameters when B generates B's own key pair.
         */
        AlgorithmParameterSpec algParamSpecFromAPubKey = ((ECPublicKey) aPubKey).getParams();
        // System.out.println ("dhParamSpecFromApubKey P = " +
        // dhParamFromAPubKey.getP());
        // System.out.println ("dhParamSpecFromApubKey G = " +
        // dhParamFromAPubKey.getG());
        // B creates own DH key pair
        // System.out.println("B: Generate DH keypair ...");
        KeyPairGenerator bKpairGen = KeyPairGenerator.getInstance("EC", providerNameY);
        bKpairGen.initialize(algParamSpecFromAPubKey);
        KeyPair bKpair = bKpairGen.generateKeyPair();

        // B creates and initializes DH KeyAgreement object
        // System.out.println("B: Initialization ...");
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", providerNameY);
        bKeyAgree.init(bKpair.getPrivate());

        // B encodes public key, and sends it over to A.
        byte[] bPubKeyEnc = bKpair.getPublic().getEncoded();
        // System.out.println ("B's publicKey as created by b" + bKpair.getPublic());

        /*
         * A uses B's public key for the first (and only) phase of A's version of the DH
         * protocol. Before A can do so, A has to instantiate a DH public key from B's
         * encoded key material.
         */
        KeyFactory aKeyFac = KeyFactory.getInstance("EC", providerNameX);
        x509KeySpec = new X509EncodedKeySpec(bPubKeyEnc);
        PublicKey bPubKey = aKeyFac.generatePublic(x509KeySpec);

        aKeyAgree.doPhase(bPubKey, true);

        /*
         * B uses A's public key for the first (and only) phase of B's version of the DH
         * protocol.
         */

        bKeyAgree.doPhase(aPubKey, true);

        /*
         * At this stage, both A and B have completed the DH key agreement protocol.
         * Both generate the (same) shared secret.
         */
        byte[] aSharedSecret = null;
        byte[] bSharedSecret = null;

        try {
            aSharedSecret = aKeyAgree.generateSecret();
            int aLen = aSharedSecret.length;
            bSharedSecret = new byte[aLen];

        } catch (Exception e) {
            System.out.println(e.getMessage());
        } // provide output buffer of required size
        bKeyAgree.generateSecret(bSharedSecret, 0);

        if (!java.util.Arrays.equals(aSharedSecret, bSharedSecret)) {
            System.out.println("A secret: " + BaseUtils.bytesToHex(aSharedSecret));
            System.out.println("B secret: " + BaseUtils.bytesToHex(bSharedSecret));

            System.out.println(
                    "KeyPairA.privKey=" + BaseUtils.bytesToHex(aKpair.getPrivate().getEncoded()));
            System.out.println(
                    "KeyPairA.publicKey=" + BaseUtils.bytesToHex(aKpair.getPublic().getEncoded()));

            System.out.println(
                    "KeyPairB.privKey=" + BaseUtils.bytesToHex(bKpair.getPrivate().getEncoded()));
            System.out.println(
                    "KeyPairB.publicKey=" + BaseUtils.bytesToHex(bKpair.getPublic().getEncoded()));

            throw new Exception("Shared secrets differ");
        }
        System.out.println("Shared secrets are the same");

        /*
         * Now let's create a SecretKey object using the shared secret and use it for
         * encryption. First, we generate SecretKeys for the "AES" algorithm (based on
         * the raw shared secret data) and Then we use AES in CBC mode, which requires
         * an initialization vector (IV) parameter. Note that you have to use the same
         * IV for encryption and decryption: If you use a different IV for decryption
         * than you used for encryption, decryption will fail.
         *
         * If you do not specify an IV when you initialize the Cipher object for
         * encryption, the underlying implementation will generate a random one, which
         * you have to retrieve using the javax.crypto.Cipher.getParameters() method,
         * which returns an instance of java.security.AlgorithmParameters. You need to
         * transfer the contents of that object (e.g., in encoded format, obtained via
         * the AlgorithmParameters.getEncoded() method) to the party who will do the
         * decryption. When initializing the Cipher for decryption, the (reinstantiated)
         * AlgorithmParameters object must be explicitly passed to the Cipher.init()
         * method.
         */
        // System.out.println("Use shared secret as SecretKey object ...");
        SecretKeySpec bAesKey = new SecretKeySpec(bSharedSecret, 0, 16, "AES");
        SecretKeySpec aAesKey = new SecretKeySpec(aSharedSecret, 0, 16, "AES");

        /*
         * B encrypts, using AES in CBC mode
         */
        if (providerNameX.equalsIgnoreCase("SunEC")) {
            providerNameX = "SunJCE";
        }
        Cipher bCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", providerNameX);
        bCipher.init(Cipher.ENCRYPT_MODE, bAesKey);
        byte[] cleartext = "This is just an example".getBytes();
        byte[] ciphertext = bCipher.doFinal(cleartext);

        // Retrieve the parameter that was used, and transfer it to A in
        // encoded format
        byte[] encodedParams = bCipher.getParameters().getEncoded();

        /*
         * A decrypts, using AES in CBC mode
         */

        // Instantiate AlgorithmParameters object from parameter encoding
        // obtained from B
        AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES", providerNameX);
        aesParams.init(encodedParams);
        Cipher aCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", providerNameX);
        aCipher.init(Cipher.DECRYPT_MODE, aAesKey, aesParams);
        byte[] recovered = aCipher.doFinal(ciphertext);
        if (!java.util.Arrays.equals(cleartext, recovered))
            throw new Exception("AES in CBC mode recovered text is " + "different from cleartext");
        System.out.println("AES in CBC mode recovered text is " + "same as cleartext");
    }


    void compute_ecdh_key_sameKeyPairGenerator(String idString,
            AlgorithmParameterSpec algParameterSpec, String providerA, String providerB)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchProviderException, InvalidKeyException {
        //final String methodName = "compute_ecdh_key_sameKeyPairGenerator" + "_" + idString;

        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("EC", providerA);
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
        //        System.out.println("KeyPairA.privKey=" + BaseUtils.bytesToHex(keyPairA.getPrivate().getEncoded()));
        //        System.out.println("KeyPairA.publicKey=" + BaseUtils.bytesToHex(keyPairA.getPublic().getEncoded()));

        // set up
        KeyAgreement keyAgreeA = null;
        try {
            keyAgreeA = KeyAgreement.getInstance("ECDH", providerA);
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

        KeyPair keyPairB = kpg.generateKeyPair();
        //        System.out.println("KeyPairB.privKey=" + BaseUtils.bytesToHex(keyPairB.getPrivate().getEncoded()));
        //        System.out.println("KeyPairB.publicKey=" + BaseUtils.bytesToHex(keyPairB.getPublic().getEncoded()));

        KeyAgreement keyAgreeB = null;
        try {
            keyAgreeB = KeyAgreement.getInstance("ECDH", providerB);
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
}

