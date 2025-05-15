/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KDF;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestHKDF extends BaseTestJunit5 {

    public String testName;
    public String algName;
    public byte[] IKM;
    public byte[] salt;
    public byte[] info;
    public int outLen;
    public byte[] expectedPRK;
    public byte[] expectedOKM;

    Provider provider = null;

    String HKDF_KA[][] = {

            {"SHA256", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",

                    "000102030405060708090a0b0c",

                    "f0f1f2f3f4f5f6f7f8f9",

                    "077709362c2e32df0ddc3f0dc47bba63" + "90b6c73bb50f9c3122ec844ad7c2b3e5",

                    "3cb25f25faacd57a90434f64d0362f2a" + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                            + "34007208d5b887185865",
                    "42"},
            {"SHA256", "000102030405060708090a0b0c0d0e0f" + "101112131415161718191a1b1c1d1e1f"
                    + "202122232425262728292a2b2c2d2e2f" + "303132333435363738393a3b3c3d3e3f"
                    + "404142434445464748494a4b4c4d4e4f",

                    "606162636465666768696a6b6c6d6e6f" + "707172737475767778797a7b7c7d7e7f"
                            + "808182838485868788898a8b8c8d8e8f"
                            + "909192939495969798999a9b9c9d9e9f"
                            + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",

                    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                            + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                            + "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                            + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",

                    "06a6b88c5853361a06104c9ceb35b45c" + "ef760014904671014a193f40c15fc244",

                    "b11e398dc80327a1c8e7f78c596a4934" + "4f012eda2d4efad8a050cc4c19afa97c"
                            + "59045a99cac7827271cb41c65e590e09"
                            + "da3275600c2f09b8367793a9aca3db71"
                            + "cc30c58179ec3e87c14c01d5c1f3434f" + "1d87",
                    "82"},
            {"SHA256", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "",
                    "19ef24a32c717b167f33a91d6f648bdf" + "96596776afdb6377ac434c1c293ccb04",

                    "8da4e775a563c18f715f802a063c5a31" + "b8a11f5c5ee1879ec3454e5f3c738d2d"
                            + "9d201395faa4b61a96c8",
                    "42"},};

    @Test
    public void testHKDF256() throws Exception {
        aesHKDF(192, "HKDF-SHA256", "AES", "AES", getProviderName());
    }

    @Test
    public void testHKDF384() throws Exception {
        aesHKDF(256, "HKDF-SHA384", "AES", "AES", getProviderName());
    }

    @Test
    public void testHKDF512() throws Exception {
        aesHKDF(256, "HKDF-SHA512", "AES", "AES", getProviderName());
    }

    @Test
    public void test3DesHKDF256() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        String curveName = "secp256r1";

        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support 3DES. So skip the test
            return;
        }

        ECGenParameterSpec ecgn = new ECGenParameterSpec(curveName);
        byte[] sharedSecret = compute_ecdh_key(curveName, ecgn, getProviderName(), getProviderName());

        javax.crypto.spec.HKDFParameterSpec derive = javax.crypto.spec.HKDFParameterSpec.ofExtract().addIKM(sharedSecret).thenExpand(null, (192 / 8));
        KDF hkdfDerive = KDF.getInstance("HKDF-SHA256", getProviderName());
        SecretKey calcOkm = hkdfDerive.deriveKey("DESede", derive);

        String strToEncrypt = "Hello string to be encrypted";
        byte[] encryptedBytes = encrypt(calcOkm, strToEncrypt, "DESede/CBC/PKCS5Padding");
        String plainStr = decrypt(calcOkm, encryptedBytes, "DESede/CBC/PKCS5Padding");
        assertTrue(plainStr.equals(strToEncrypt));
    }

    @Test
    public void testInvalidKeyAlgorithms1() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

        byte[] sharedSecret = new byte[64];

        try {
            javax.crypto.spec.HKDFParameterSpec derive = javax.crypto.spec.HKDFParameterSpec.ofExtract().addIKM(sharedSecret).thenExpand(null, 64);
            KDF hkdfDerive = KDF.getInstance("HKDF-SHA256", getProviderName());
            hkdfDerive.deriveKey(null, derive);
            assertTrue(false);
        } catch (NullPointerException npe) {
            assertTrue(true);
        }

    }

    @Test
    public void testInvalidKeyAlgorithms2() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

        byte[] sharedSecret = new byte[64];

        try {
            javax.crypto.spec.HKDFParameterSpec derive = javax.crypto.spec.HKDFParameterSpec.ofExtract().addIKM(sharedSecret).thenExpand(null, (255 * 40));
            KDF hkdfDerive = KDF.getInstance("HKDF-SHA256", getProviderName());
            hkdfDerive.deriveKey("AES", derive);
            assertTrue(false);
        } catch (InvalidAlgorithmParameterException iae) {
            assertTrue(true);
        }

    }

    @Test
    public void testEcdhHKDF256() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        String curveName = "secp256r1";

        ECGenParameterSpec ecgn = new ECGenParameterSpec(curveName);
        byte[] sharedSecret = compute_ecdh_key(curveName, ecgn, getProviderName(), getProviderName());

        javax.crypto.spec.HKDFParameterSpec derive = javax.crypto.spec.HKDFParameterSpec.ofExtract().addIKM(sharedSecret).thenExpand(null, (256 / 8));
        KDF hkdfDerive = KDF.getInstance("HKDF-SHA256", getProviderName());
        SecretKey calcOkm = hkdfDerive.deriveKey("AES", derive);

        String strToEncrypt = "Hello string to be encrypted";
        byte[] encryptedBytes = encrypt(calcOkm, strToEncrypt, "AES/ECB/PKCS5Padding");
        String plainStr = decrypt(calcOkm, encryptedBytes, "AES/ECB/PKCS5Padding");
        assertTrue(plainStr.equals(strToEncrypt));
    }

    @Test
    public void testEcdhHKDF512() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        String curveName = "secp256r1";

        ECGenParameterSpec ecgn = new ECGenParameterSpec(curveName);
        byte[] sharedSecret = compute_ecdh_key(curveName, ecgn, getProviderName(), getProviderName());

        javax.crypto.spec.HKDFParameterSpec derive = javax.crypto.spec.HKDFParameterSpec.ofExtract().addIKM(sharedSecret).thenExpand(null, (256 / 8));
        KDF hkdfDerive = KDF.getInstance("HKDF-SHA512", getProviderName());
        SecretKey calcOkm = hkdfDerive.deriveKey("AES", derive);
        

        String strToEncrypt = "Hello string to be encrypted";
        byte[] encryptedBytes = encrypt(calcOkm, strToEncrypt, "AES/ECB/PKCS5Padding");
        String plainStr = decrypt(calcOkm, encryptedBytes, "AES/ECB/PKCS5Padding");
        assertTrue(plainStr.equals(strToEncrypt));
    }

    private void aesHKDF(int aesKeySize, String hashAlg, String extractAlg, String expandAlg,
            String providerName) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, IOException, InvalidKeyException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(aesKeySize);
        SecretKey psk = keyGen.generateKey(); // System.out.println("Generated secretKey=" + psk);

        MessageDigest md = MessageDigest.getInstance(hashAlg.replace("HKDF-", ""),
                providerName);
        byte[] zeros = new byte[md.getDigestLength()];

        KDF hkdfExtract = KDF.getInstance(hashAlg, getProviderName());
        javax.crypto.spec.HKDFParameterSpec extractOnly = javax.crypto.spec.HKDFParameterSpec.ofExtract().addIKM(psk).addSalt(zeros).extractOnly();
        SecretKey earlySecret = hkdfExtract.deriveKey(extractAlg, extractOnly);
        assertTrue(earlySecret != null);

        byte[] label = ("tls13 res binder").getBytes();
        byte[] hkdfInfo = createHkdfInfo(label, new byte[0], md.getDigestLength());
        KDF hkdfExpand = KDF.getInstance(hashAlg, getProviderName());
        javax.crypto.spec.HKDFParameterSpec expandOnly = javax.crypto.spec.HKDFParameterSpec.expandOnly(earlySecret, hkdfInfo, (aesKeySize / 8));
        SecretKey expandSecretKey = hkdfExpand.deriveKey(expandAlg, expandOnly);
        assertTrue(expandSecretKey != null);

        String strToEncrypt = "Hello string to be encrypted";
        byte[] encryptedBytes = encrypt(expandSecretKey, strToEncrypt, "AES/ECB/PKCS5Padding");
        String plainStr = decrypt(expandSecretKey, encryptedBytes, "AES/ECB/PKCS5Padding");
        assertTrue(plainStr.equals(strToEncrypt));
    }

    private byte[] encrypt(SecretKey secretKey, String strToEncrypt, String cipherAlgorithm)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException,
            InvalidAlgorithmParameterException {

        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        IvParameterSpec iv = null;
        if (cipherAlgorithm.startsWith("DESede")) {
            iv = new IvParameterSpec(new byte[8]);
        } else if (cipherAlgorithm.startsWith("AES")) {
            iv = new IvParameterSpec(new byte[16]);
        }

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        return cipher.doFinal(strToEncrypt.getBytes());
    }

    private String decrypt(SecretKey secretKey, byte[] encryptedBytes, String cipherAlgorithm)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException,
            InvalidAlgorithmParameterException {

        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        IvParameterSpec iv = null;
        if (cipherAlgorithm.startsWith("DESede")) {
            iv = new IvParameterSpec(new byte[8]);
        } else if (cipherAlgorithm.startsWith("AES")) {
            iv = new IvParameterSpec(new byte[16]);
        }
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        return new String(cipher.doFinal(encryptedBytes));

    }

    private static byte[] createHkdfInfo(byte[] label, byte[] context, int length)
            throws IOException {
        byte[] info = new byte[4 + label.length];
        ByteBuffer m = ByteBuffer.wrap(info);
        try {
            Record.putInt16(m, length);
            Record.putBytes8(m, label);
            Record.putInt8(m, 0x00); // zero-length context
        } catch (IOException ioe) {
            // unlikely
            throw new RuntimeException("Unexpected exception", ioe);
        }

        return info;

    }

    private static byte[] hexStringToByteArray(String string) {
        String s = string.trim().replaceAll(" +", ""); // remove all spaces

        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(s.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    @Test
    public void testThroughProvider() throws Exception {
        try {
            for (int i = 0; i < HKDF_KA.length; i++) {
                byte[] ikmArray = hexStringToByteArray(HKDF_KA[i][1]);
                byte[] saltArray = hexStringToByteArray(HKDF_KA[i][2]);
                byte[] infoArray = hexStringToByteArray(HKDF_KA[i][3]);
                byte[] prkArray = hexStringToByteArray(HKDF_KA[i][4]);
                byte[] okmArray = hexStringToByteArray(HKDF_KA[i][5]);
                int okmLength = Integer.parseInt(HKDF_KA[i][6]);
                assert (ikmArray != null);
                assert (saltArray != null);
                assert (infoArray != null);
                assert (prkArray != null);
                assert (okmArray != null);
                assert (okmLength > 0);
                // System.out.println("i=" + i);

                KDF hkdfExtract = KDF.getInstance("HKDF-SHA256", getProviderName());

                if (HKDF_KA[i][2].equals("")) {
                    saltArray = new byte[0];
                }

                javax.crypto.spec.HKDFParameterSpec extractOnly = javax.crypto.spec.HKDFParameterSpec.ofExtract().addIKM(ikmArray).addSalt(saltArray).extractOnly();
                SecretKey calcPrk = hkdfExtract.deriveKey("TlsEarlySecret", extractOnly);

                byte[] calcPrkArray = calcPrk.getEncoded();
                assertArrayEquals(prkArray, calcPrkArray, "Calculated key doesn't match hardcoded one");

                KDF hkdfExpand = KDF.getInstance("HKDF-SHA256", getProviderName());
                SecretKey prk = new SecretKeySpec(prkArray, "AES");
                javax.crypto.spec.HKDFParameterSpec expandOnly = javax.crypto.spec.HKDFParameterSpec.expandOnly(prk, infoArray, okmLength);
                SecretKey calcOkm = hkdfExpand.deriveKey("TlsEarlySecret", expandOnly);

                byte[] calcOkmArray = calcOkm.getEncoded();
                assertArrayEquals(okmArray, calcOkmArray, "Calculated okm doesn't match hardcoded one");
                assertTrue(calcOkmArray.length == okmLength);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            assertTrue(false);

        }
    }

    // One OCK call does both extract and derive
    @Test
    public void testDerive() throws Exception {
        try {
            for (int i = 0; i < HKDF_KA.length; i++) {
                byte[] ikmArray = hexStringToByteArray(HKDF_KA[i][1]);
                byte[] saltArray = hexStringToByteArray(HKDF_KA[i][2]);
                byte[] infoArray = hexStringToByteArray(HKDF_KA[i][3]);
                byte[] prkArray = hexStringToByteArray(HKDF_KA[i][4]);
                byte[] okmArray = hexStringToByteArray(HKDF_KA[i][5]);
                int okmLength = Integer.parseInt(HKDF_KA[i][6]);
                assert (ikmArray != null);
                assert (saltArray != null);
                assert (infoArray != null);
                assert (prkArray != null);
                assert (okmArray != null);
                assert (okmLength > 0);
                // System.out.println("i=" + i);

                if (HKDF_KA[i][2].equals("")) {
                    saltArray = new byte[0];
                }

                javax.crypto.spec.HKDFParameterSpec derive = javax.crypto.spec.HKDFParameterSpec.ofExtract().addIKM(ikmArray).addSalt(saltArray).thenExpand(infoArray, okmLength);
                KDF hkdfDerive = KDF.getInstance("HKDF-SHA256", getProviderName());
                SecretKey calcOkm = hkdfDerive.deriveKey("TlsEarlySecret", derive);

                byte[] calcOkmArray = calcOkm.getEncoded();
                assertArrayEquals(okmArray, calcOkmArray, "Calculated okm doesn't match hardcoded one");
                assertTrue(calcOkmArray.length == okmLength);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            assertTrue(false);

        }
    }

    byte[] compute_ecdh_key(String idString, AlgorithmParameterSpec algParameterSpec,
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
        // System.out.println("KeyPairA.privKey=" +
        // BaseUtils.bytesToHex(keyPairA.getPrivate().getEncoded()));
        // System.out.println("KeyPairA.publicKey=" +
        // BaseUtils.bytesToHex(keyPairA.getPublic().getEncoded()));

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
        // System.out.println(methodName + " sharedSecretA = " +
        // BaseUtils.bytesToHex(sharedSecretA));
        // System.out.println(methodName + " sharedSecretB = " +
        // BaseUtils.bytesToHex(sharedSecretB));

        assertTrue(Arrays.equals(sharedSecretA, sharedSecretB));
        return sharedSecretA;

    }

}
