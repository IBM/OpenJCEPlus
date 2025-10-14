/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KDF;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestHKDFInterop extends BaseTestJunit5Interop {
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
                    "42"}, };

    @Test
    public void testJcePlustoBC() throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException {

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

            if (HKDF_KA[i][2].equals("")) {
                saltArray = new byte[0];
            }

            KDF hkdfExtract = KDF.getInstance("HKDF-SHA256", getProviderName());
            javax.crypto.spec.HKDFParameterSpec extractOnly = javax.crypto.spec.HKDFParameterSpec.ofExtract().addIKM(ikmArray).addSalt(saltArray).extractOnly();
            SecretKey calcPrk = hkdfExtract.deriveKey("TlsEarlySecret", extractOnly);
            byte[] calcPrkArray = calcPrk.getEncoded();
            assertArrayEquals(prkArray, calcPrkArray, "Calculated key doesn't match hardcoded one");

            KDF hkdfExpand = KDF.getInstance("HKDF-SHA256", getProviderName());
            javax.crypto.spec.HKDFParameterSpec expandOnly = javax.crypto.spec.HKDFParameterSpec.expandOnly(calcPrk, infoArray, okmLength);
            SecretKey calcOkm = hkdfExpand.deriveKey("TlsEarlySecret", expandOnly);
            byte[] calcOkmArray = calcOkm.getEncoded();

            assertArrayEquals(okmArray, calcOkmArray, "Calculated okm doesn't match hardcoded one");
            assertTrue (calcOkmArray.length == okmLength);

            SHA256Digest bcDigest = new SHA256Digest();

            HKDFBytesGenerator hkdfBytesGeneratorBC = new HKDFBytesGenerator(bcDigest);
            HKDFParameters hkdfParametersBC = new HKDFParameters(ikmArray, saltArray,
                    infoArray);
            hkdfBytesGeneratorBC.init(hkdfParametersBC);
            byte[] okmBC = new byte[(int) okmLength];

            hkdfBytesGeneratorBC.generateBytes(okmBC, 0, (int) okmLength);

            assertArrayEquals(calcOkmArray, okmBC, "OpenJCEPlus and BC results don't match");
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

                if (HKDF_KA[i][2].equals("")) {
                    saltArray = new byte[0];
                }

                javax.crypto.spec.HKDFParameterSpec derive = javax.crypto.spec.HKDFParameterSpec.ofExtract().addIKM(ikmArray).addSalt(saltArray).thenExpand(infoArray, okmLength);
                KDF hkdfDerive = KDF.getInstance("HKDF-SHA256", getProviderName());
                SecretKey calcOkm = hkdfDerive.deriveKey("TlsEarlySecret", derive);
                byte[] calcOkmArray = calcOkm.getEncoded();
                assertArrayEquals(okmArray, calcOkmArray);
                assertTrue(calcOkmArray.length == okmLength);

                SHA256Digest bcDigest = new SHA256Digest();
                HKDFBytesGenerator hkdfBytesGeneratorBC = new HKDFBytesGenerator(bcDigest);
                HKDFParameters hkdfParametersBC = new HKDFParameters(ikmArray, saltArray,
                        infoArray);
                hkdfBytesGeneratorBC.init(hkdfParametersBC);
                byte[] okmBC = new byte[(int) okmLength];

                hkdfBytesGeneratorBC.generateBytes(okmBC, 0, (int) okmLength);
                assertArrayEquals(calcOkmArray, okmBC, "OpenJCEPlus and BC results don't match");
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            assertTrue(false);

        }
    }

    @Test
    public void testEcdhHKDF256PlusToBC() throws InvalidKeyException, NoSuchAlgorithmException,
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
        String plainStr = decrypt(calcOkm, encryptedBytes, "AES/ECB/PKCS5Padding",
                getInteropProviderName());
        assertTrue(plainStr.equals(strToEncrypt));


    }

    @Test
    public void testEcdhHKDF256BCtoPlus() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        String curveName = "secp256r1";

        ECGenParameterSpec ecgn = new ECGenParameterSpec(curveName);
        byte[] sharedSecret = compute_ecdh_key(curveName, ecgn, getInteropProviderName(),
                getInteropProviderName());

        javax.crypto.spec.HKDFParameterSpec derive = javax.crypto.spec.HKDFParameterSpec.ofExtract().addIKM(sharedSecret).thenExpand(null, (256 / 8));
        KDF hkdfDerive = KDF.getInstance("HKDF-SHA256", getProviderName());
        SecretKey calcOkm = hkdfDerive.deriveKey("AES", derive);

        String strToEncrypt = "Hello string to be encrypted";
        byte[] encryptedBytes = encrypt(calcOkm, strToEncrypt, "AES/ECB/PKCS5Padding",
                getInteropProviderName());
        String plainStr = decrypt(calcOkm, encryptedBytes, "AES/ECB/PKCS5Padding");
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
        } else if (cipherAlgorithm.startsWith("AES") && !cipherAlgorithm.contains("/ECB/")) {
            iv = new IvParameterSpec(new byte[16]);
        }

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        return cipher.doFinal(strToEncrypt.getBytes());
    }

    private byte[] encrypt(SecretKey secretKey, String strToEncrypt, String cipherAlgorithm,
            String providerName)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException,
            InvalidAlgorithmParameterException, NoSuchProviderException {

        Cipher cipher = Cipher.getInstance(cipherAlgorithm, providerName);
        IvParameterSpec iv = null;
        if (cipherAlgorithm.startsWith("DESede")) {
            iv = new IvParameterSpec(new byte[8]);
        } else if (cipherAlgorithm.startsWith("AES") && !cipherAlgorithm.contains("/ECB/")) {
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
        } else if (cipherAlgorithm.startsWith("AES") && !cipherAlgorithm.contains("/ECB/")) {
            iv = new IvParameterSpec(new byte[16]);
        }
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        return new String(cipher.doFinal(encryptedBytes));

    }

    private String decrypt(SecretKey secretKey, byte[] encryptedBytes, String cipherAlgorithm,
            String providerName)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException,
            InvalidAlgorithmParameterException, NoSuchProviderException {

        Cipher cipher = Cipher.getInstance(cipherAlgorithm, providerName);
        IvParameterSpec iv = null;
        if (cipherAlgorithm.startsWith("DESede")) {
            iv = new IvParameterSpec(new byte[8]);
        } else if (cipherAlgorithm.startsWith("AES") && !cipherAlgorithm.contains("/ECB/")) {
            iv = new IvParameterSpec(new byte[16]);
        }
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        return new String(cipher.doFinal(encryptedBytes));

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

    byte[] compute_ecdh_key(String idString, AlgorithmParameterSpec algParameterSpec,
            String providerA, String providerB) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeyException {


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

        assertTrue(Arrays.equals(sharedSecretA, sharedSecretB));
        return sharedSecretA;

    }
}
