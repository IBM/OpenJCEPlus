/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import ibm.security.internal.spec.HKDFExpandParameterSpec;
import ibm.security.internal.spec.HKDFExtractParameterSpec;
import ibm.security.internal.spec.HKDFParameterSpec;
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
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class BaseTestHKDF extends ibm.jceplus.junit.base.BaseTest {

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
                    "42"},
            {"SHA1", "0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9",
                    "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
                    "085a01ea1b10f36933068b56efa5ad81" + "a4f14b822f5b091568a9cdd4f155fda2"
                            + "c22e422478d305f3f896",
                    "42"},
            {"SHA1", "000102030405060708090a0b0c0d0e0f" + "101112131415161718191a1b1c1d1e1f"
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

                    "8adae09a2a307059478d309b26c4115a224cfaf6",

                    "0bd770a74d1160f7c9f12cd5912a06eb" + "ff6adcae899d92191fe4305673ba2ffe"
                            + "8fa3f1a4e5ad79f3f334b3b202b2173c"
                            + "486ea37ce3d397ed034c7f9dfeb15c5e"
                            + "927336d0441f4c4300e2cff0d0900b52" + "d3b4",
                    "82"},
            {"SHA1", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "",
                    "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
                    "0ac1af7002b3d761d1e55298da9d0506" + "b9ae52057220a306e07b6b87e8df21d0"
                            + "ea00033de03984d34918",
                    "42"},
            {"SHA1", "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "", "",
                    "2adccada18779e7c2077ad2eb19d3f3e731385dd", "2c91117204d745f3500d636a62f64f0a"
                            + "b3bae548aa53d423b0d1f27ebba6f5e5" + "673a081d70cce7acfc48",
                    "42"},};

    // --------------------------------------------------------------------------
    //
    //
    public BaseTestHKDF(String providerName) {
        super(providerName);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {

    }

    // --------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    public void testHKDF1() throws Exception {
        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS does not support SHA1. So skip the test
            return;
        }

        aesHKDF(128, "kda-hkdf-with-sha1", "AES", "AES", providerName);
        aesHKDF(128, "kda-hkdf-with-sha-1", "AES", "AES", providerName);
    }

    public void testHKDF224() throws Exception {

        aesHKDF(192, "kda-hkdf-with-sha224", "AES", "AES", providerName);
        aesHKDF(192, "kda-hkdf-with-sha-224", "AES", "AES", providerName);
    }

    public void testHKDF256() throws Exception {

        aesHKDF(192, "kda-hkdf-with-sha256", "AES", "AES", providerName);
        aesHKDF(192, "kda-hkdf-with-sha-256", "AES", "AES", providerName);
    }

    public void testHKDF384() throws Exception {

        aesHKDF(256, "kda-hkdf-with-sha384", "AES", "AES", providerName);
        aesHKDF(256, "kda-hkdf-with-sha-384", "AES", "AES", providerName);
    }

    public void testHKDF512() throws Exception {

        aesHKDF(256, "kda-hkdf-with-sha512", "AES", "AES", providerName);
        aesHKDF(256, "kda-hkdf-with-sha-512", "AES", "AES", providerName);
    }

    public void test3DesHKDF256() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        String curveName = "secp256r1";

        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS does not support 3DES. So skip the test
            return;
        }

        ECGenParameterSpec ecgn = new ECGenParameterSpec(curveName);
        byte[] sharedSecret = compute_ecdh_key(curveName, ecgn, providerName, providerName);

        HKDFParameterSpec hkdfDeriveSpec = new HKDFParameterSpec(sharedSecret, null, null,
                (long) (192 / 8), "DESede");
        KeyGenerator hkdfDerive = KeyGenerator.getInstance("kda-hkdf-with-sha256", providerName);
        hkdfDerive.init(hkdfDeriveSpec);
        SecretKey calcOkm = hkdfDerive.generateKey();
        String strToEncrypt = "Hello string to be encrypted";
        byte[] encryptedBytes = encrypt(calcOkm, strToEncrypt, "DESede/CBC/PKCS5Padding");
        String plainStr = decrypt(calcOkm, encryptedBytes, "DESede/CBC/PKCS5Padding");
        assertTrue(plainStr.equals(strToEncrypt));

    }

    public void testLongOKM() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        String curveName = "secp256r1";

        ECGenParameterSpec ecgn = new ECGenParameterSpec(curveName);
        byte[] sharedSecret = compute_ecdh_key(curveName, ecgn, providerName, providerName);

        try {
            new HKDFParameterSpec(sharedSecret, null, null,
                    (long) ((255 * 64) + 1), "AES");
            assertTrue(false);
        } catch (IllegalArgumentException invalidPE) {
            assertTrue(true);
        }

    }

    public void testInvalidKeyAlgorithms1() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

        byte[] sharedSecret = new byte[64];

        try {
            new HKDFParameterSpec(sharedSecret, null, null,
                    (long) 64, null);
            assertTrue(false);
        } catch (IllegalArgumentException iae) {
            assertTrue(true);
        }

    }



    public void testInvalidKeyAlgorithms2() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

        byte[] sharedSecret = new byte[64];

        try {
            HKDFParameterSpec hkdfDeriveSpec = new HKDFParameterSpec(sharedSecret, null, null,
                    (long) ((255 * 40)), "AES");
            KeyGenerator hkdfDerive = KeyGenerator.getInstance("kda-hkdf-with-sha256",
                    providerName);
            hkdfDerive.init(hkdfDeriveSpec);
            assertTrue(false);
        } catch (InvalidAlgorithmParameterException iae) {
            assertTrue(true);
        }

    }

    public void testEcdhHKDF1() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS does not support SHA1. Skip test
            return;
        }
        String curveName = "secp256r1";

        ECGenParameterSpec ecgn = new ECGenParameterSpec(curveName);
        byte[] sharedSecret = compute_ecdh_key(curveName, ecgn, providerName, providerName);

        HKDFParameterSpec hkdfDeriveSpec = new HKDFParameterSpec(sharedSecret, null, null,
                (long) (192 / 8), "AES");
        KeyGenerator hkdfDerive = KeyGenerator.getInstance("kda-hkdf-with-sha1", providerName);
        hkdfDerive.init(hkdfDeriveSpec);
        SecretKey calcOkm = hkdfDerive.generateKey();
        String strToEncrypt = "Hello string to be encrypted";
        byte[] encryptedBytes = encrypt(calcOkm, strToEncrypt, "AES/ECB/PKCS5Padding");
        String plainStr = decrypt(calcOkm, encryptedBytes, "AES/ECB/PKCS5Padding");
        assertTrue(plainStr.equals(strToEncrypt));

    }

    public void testEcdhHKDF256() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        String curveName = "secp256r1";

        ECGenParameterSpec ecgn = new ECGenParameterSpec(curveName);
        byte[] sharedSecret = compute_ecdh_key(curveName, ecgn, providerName, providerName);

        HKDFParameterSpec hkdfDeriveSpec = new HKDFParameterSpec(sharedSecret, null, null,
                (long) (256 / 8), "AES");
        KeyGenerator hkdfDerive = KeyGenerator.getInstance("kda-hkdf-with-sha256", providerName);
        hkdfDerive.init(hkdfDeriveSpec);
        SecretKey calcOkm = hkdfDerive.generateKey();
        String strToEncrypt = "Hello string to be encrypted";
        byte[] encryptedBytes = encrypt(calcOkm, strToEncrypt, "AES/ECB/PKCS5Padding");
        String plainStr = decrypt(calcOkm, encryptedBytes, "AES/ECB/PKCS5Padding");
        assertTrue(plainStr.equals(strToEncrypt));

    }

    public void testEcdhHKDF512() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        String curveName = "secp256r1";

        ECGenParameterSpec ecgn = new ECGenParameterSpec(curveName);
        byte[] sharedSecret = compute_ecdh_key(curveName, ecgn, providerName, providerName);

        HKDFParameterSpec hkdfDeriveSpec = new HKDFParameterSpec(sharedSecret, null, null,
                (long) (256 / 8), "AES");
        KeyGenerator hkdfDerive = KeyGenerator.getInstance("kda-hkdf-with-sha512", providerName);
        hkdfDerive.init(hkdfDeriveSpec);
        SecretKey calcOkm = hkdfDerive.generateKey();
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

        MessageDigest md = MessageDigest.getInstance(hashAlg.replace("kda-hkdf-with-", ""),
                providerName);
        KeyGenerator hkdfExtract = KeyGenerator.getInstance(hashAlg, providerName);
        byte[] zeros = new byte[md.getDigestLength()];

        hkdfExtract.init(new HKDFExtractParameterSpec(psk.getEncoded(), zeros, extractAlg));
        SecretKey earlySecret = hkdfExtract.generateKey();
        assert (earlySecret != null);

        byte[] label = ("tls13 res binder").getBytes();

        byte[] hkdfInfo = createHkdfInfo(label, new byte[0], md.getDigestLength());
        KeyGenerator hkdfExpand = KeyGenerator.getInstance(hashAlg, providerName);
        hkdfExpand.init(new HKDFExpandParameterSpec(earlySecret, hkdfInfo,
                (aesKeySize / 8)/* md.getDigestLength() */, expandAlg));
        SecretKey expandSecretKey = hkdfExpand.generateKey();
        assert (expandSecretKey != null);
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

    public void testThroguhProvider() throws Exception {
        try {
            // HKDF hkdf = HKDF.getInstance("kda-hkdf-with-sha256", providerName);

            for (int i = 0; i < HKDF_KA.length; i++) {

                String digestAlgo = HKDF_KA[i][0];
                byte[] ikmArray = hexStringToByteArray(HKDF_KA[i][1]);
                byte[] saltArray = hexStringToByteArray(HKDF_KA[i][2]);
                byte[] infoArray = hexStringToByteArray(HKDF_KA[i][3]);
                byte[] prkArray = hexStringToByteArray(HKDF_KA[i][4]);
                byte[] okmArray = hexStringToByteArray(HKDF_KA[i][5]);
                long okmLength = Long.parseLong(HKDF_KA[i][6]);
                assert (ikmArray != null);
                assert (saltArray != null);
                assert (infoArray != null);
                assert (prkArray != null);
                assert (okmArray != null);
                assert (okmLength > 0);
                // System.out.println("i=" + i);
                if (digestAlgo.equals("SHA256")) {
                    KeyGenerator hkdfExtract = KeyGenerator.getInstance("kda-hkdf-with-sha256",
                            providerName);
                    // System.out.println("HKDF digest algorithm " +
                    // hkdfExtract.getDigestAlgorithm());

                    if (HKDF_KA[i][2].equals("")) {
                        saltArray = null;
                    }
                    HKDFExtractParameterSpec extractSpec = new HKDFExtractParameterSpec(ikmArray,
                            saltArray, "TlsEarlySecret");
                    hkdfExtract.init(extractSpec);

                    SecretKey calcPrk = hkdfExtract.generateKey();
                    byte[] calcPrkArray = calcPrk.getEncoded();
                    boolean prkequal = Arrays.equals(prkArray, calcPrkArray);
                    assert (prkequal == true);

                    KeyGenerator hkdfExpand = KeyGenerator.getInstance("kda-hkdf-with-sha256",
                            providerName);
                    HKDFExpandParameterSpec expandSpec = new HKDFExpandParameterSpec(prkArray,
                            infoArray, okmLength, "TlsEarlySecret");
                    hkdfExpand.init(expandSpec);
                    SecretKey calcOkm = hkdfExpand.generateKey();

                    byte[] calcOkmArray = calcOkm.getEncoded();
                    boolean okmequal = Arrays.equals(okmArray, calcOkmArray);
                    assert (okmequal == true);
                    assert (calcOkmArray.length == okmLength);
                } else {
                    if (providerName.equals("OpenJCEPlusFIPS")) {
                        //FIPS does not support SHA1. Skip test
                        break;
                    }
                    KeyGenerator hkdfExtract = KeyGenerator.getInstance("kda-hkdf-with-sha1",
                            providerName);
                    // System.out.println("HKDF digest algorithm " +
                    // hkdfExtract.getDigestAlgorithm());

                    if (HKDF_KA[i][2].equals("")) {
                        saltArray = null;
                    }
                    HKDFExtractParameterSpec extractSpec = new HKDFExtractParameterSpec(ikmArray,
                            saltArray, "TlsEarlySecret");
                    hkdfExtract.init(extractSpec);

                    SecretKey calcPrk = hkdfExtract.generateKey();
                    byte[] calcPrkArray = calcPrk.getEncoded();
                    boolean prkequal = Arrays.equals(prkArray, calcPrkArray);
                    assert (prkequal == true);

                    KeyGenerator hkdfExpand = KeyGenerator.getInstance("kda-hkdf-with-sha1",
                            providerName);
                    HKDFExpandParameterSpec expandSpec = new HKDFExpandParameterSpec(prkArray,
                            infoArray, okmLength, "TlsEarlySecret");
                    hkdfExpand.init(expandSpec);
                    SecretKey calcOkm = hkdfExpand.generateKey();

                    byte[] calcOkmArray = calcOkm.getEncoded();
                    boolean okmequal = Arrays.equals(okmArray, calcOkmArray);
                    assert (okmequal == true);
                    /*
                     * System.err.println("calcOkm algorithm=" + calcOkm.getAlgorithm());
                     * System.err.println("calcOkm encoded=" +
                     * BaseUtils.bytesToHex(calcOkm.getEncoded()));
                     * System.err.println("calcOkm format=" + calcOkm.getFormat());
                     */

                }
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
    public void testDerive() throws Exception {
        try {

            for (int i = 0; i < HKDF_KA.length; i++) {

                String digestAlgo = HKDF_KA[i][0];
                byte[] ikmArray = hexStringToByteArray(HKDF_KA[i][1]);
                byte[] saltArray = hexStringToByteArray(HKDF_KA[i][2]);
                byte[] infoArray = hexStringToByteArray(HKDF_KA[i][3]);
                byte[] prkArray = hexStringToByteArray(HKDF_KA[i][4]);
                byte[] okmArray = hexStringToByteArray(HKDF_KA[i][5]);
                long okmLength = Long.parseLong(HKDF_KA[i][6]);
                assert (ikmArray != null);
                assert (saltArray != null);
                assert (infoArray != null);
                assert (prkArray != null);
                assert (okmArray != null);
                assert (okmLength > 0);
                // System.out.println("i=" + i);
                if (digestAlgo.equals("SHA256")) {
                    KeyGenerator hkdfDerive = KeyGenerator.getInstance("kda-hkdf-with-sha256",
                            providerName);
                    // System.out.println("HKDF digest algorithm " +
                    // hkdfExtract.getDigestAlgorithm());

                    if (HKDF_KA[i][2].equals("")) {
                        saltArray = null;
                    }
                    HKDFParameterSpec hkdfDeriveSpec = new HKDFParameterSpec(ikmArray, saltArray,
                            infoArray, okmLength, "TlsEarlySecret");
                    hkdfDerive.init(hkdfDeriveSpec);
                    SecretKey calcOkm = hkdfDerive.generateKey();

                    byte[] calcOkmArray = calcOkm.getEncoded();
                    boolean okmequal = Arrays.equals(okmArray, calcOkmArray);
                    assert (okmequal == true);
                    assert (calcOkmArray.length == okmLength);
                } else {
                    if (providerName.equals("OpenJCEPlusFIPS")) {
                        //FIPS does not support SHA1. Skip test
                        break;
                    }

                    KeyGenerator hkdfDerive = KeyGenerator.getInstance("kda-hkdf-with-sha1",
                            providerName);
                    // System.out.println("HKDF digest algorithm " +
                    // hkdfExtract.getDigestAlgorithm());

                    if (HKDF_KA[i][2].equals("")) {
                        saltArray = null;
                    }
                    HKDFParameterSpec hkdfDeriveSpec = new HKDFParameterSpec(ikmArray, saltArray,
                            infoArray, okmLength, "TlsEarlySecret");
                    hkdfDerive.init(hkdfDeriveSpec);
                    SecretKey calcOkm = hkdfDerive.generateKey();

                    byte[] calcOkmArray = calcOkm.getEncoded();
                    boolean okmequal = Arrays.equals(okmArray, calcOkmArray);
                    assert (okmequal == true);
                    assert (calcOkmArray.length == okmLength);

                }
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
