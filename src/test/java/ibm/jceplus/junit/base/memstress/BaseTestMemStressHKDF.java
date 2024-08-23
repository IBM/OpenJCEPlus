/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base.memstress;

import ibm.security.internal.spec.HKDFExpandParameterSpec;
import ibm.security.internal.spec.HKDFExtractParameterSpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


public class BaseTestMemStressHKDF extends ibm.jceplus.junit.base.BaseTest {

    public String testName;
    public String algName;
    public byte[] IKM;
    public byte[] salt;
    public byte[] info;
    public int outLen;
    public byte[] expectedPRK;
    public byte[] expectedOKM;

    int numTimes = 100;
    boolean printheapstats = false;

    Provider provider = null;
    int keysize = 192;
    String algo = "kda-hkdf-with-sha256";

    // --------------------------------------------------------------------------
    //
    //
    public BaseTestMemStressHKDF(String providerName) {
        super(providerName);
    }

    // --------------------------------------------------------------------------
    //
    //
    public BaseTestMemStressHKDF(String providerName, String algo, int keyszie) {
        super(providerName);
        this.keysize = keyszie;
        this.algo = algo;
    }

    // --------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {
        String numTimesStr = System.getProperty("com.ibm.jceplus.memstress.numtimes");
        if (numTimesStr != null) {
            numTimes = Integer.valueOf(numTimesStr);
        }
        printheapstats = Boolean
                .valueOf(System.getProperty("com.ibm.jceplus.memstress.printheapstats"));
        System.out.println("Testing HKDF keysize=" + this.keysize + " algorihm=" + this.algo);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}



    public void testHKDF() throws Exception {
        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;
        for (int i = 0; i < numTimes; i++) {
            aesHKDF(192, "kda-hkdf-with-sha256", "AES", "AES", providerName);
            currentTotalMemory = rt.totalMemory();
            currentFreeMemory = rt.freeMemory();
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            prevUsedMemory = prevTotalMemory - prevFreeMemory;
            if (currentTotalMemory != prevTotalMemory || currentFreeMemory != prevFreeMemory) {
                if (printheapstats) {
                    System.out.println(
                            "HKDF Iteration = " + i + " " + "Total: = " + currentTotalMemory + " "
                                    + "currentUsed: = " + currentUsedMemory + " " + "freeMemory: "
                                    + currentFreeMemory + " prevUsedMemory: " + prevUsedMemory);
                }
                prevTotalMemory = currentTotalMemory;
                prevFreeMemory = currentFreeMemory;
            }
        }
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
            ibm.jceplus.junit.base.Record.putInt16(m, length);
            ibm.jceplus.junit.base.Record.putBytes8(m, label);
            ibm.jceplus.junit.base.Record.putInt8(m, 0x00); // zero-length context
        } catch (IOException ioe) {
            // unlikely
            throw new RuntimeException("Unexpected exception", ioe);
        }

        return info;

    }



}
