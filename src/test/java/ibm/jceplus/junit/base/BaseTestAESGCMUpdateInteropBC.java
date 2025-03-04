/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.lang.reflect.Method;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestAESGCMUpdateInteropBC extends BaseTestJunit5Interop {
    private final static int GCM_IV_LENGTH = 12;
    private final static int GCM_TAG_LENGTH = 16;
    private static int ARRAY_OFFSET = 16;
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();


    protected KeyGenerator aesKeyGen;
    //protected SecretKey key16;
    //protected SecretKey key32;
    protected AlgorithmParameters params = null;
    //protected Cipher cp = null;
    //protected boolean success = true;
    protected Method methodCipherUpdateAAD = null;
    //protected Constructor ctorGCMParameterSpec = null;
    //protected Method methodGCMParameterSpecSetAAD = null;
    protected int specifiedKeySize = 0;

    String[] plainTextStrArray = {"a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg",
            "abcdefgh", "abcdefghi", "abcdefghi", "abcdefghij", "abcdefghijk", "abcdefghijkl",
            "abcdefghijklm", "abcdefghijklmn", "abcdefghijklmno", "abcdefghijklmnop",
            "abcdefghijklmnopq", "abcdefghijklmnopqr", "abcdefghijklmnopqrs",
            "abcdefghijklmnopqrst", "abcdefghijklmnopqrstu", "abcdefghijklmnopqrstuv",
            "abcdefghijklmnopqrstuvw", "abcdefghijklmnopqrstuvwx", "abcdefghijklmnopqrstuvwxy",
            "abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz0123456789",
            "abcdefghijklmnopqrstuvwxyz01234567890123456789",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyza",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0123456789"};

    String[] plainTextStrArray1 = {
            //"abcdefghijklmnopqrstuvwxyz0123456789012345678901234",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyza01234",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa012345678901234"};


    private Cipher createCipher(String myProviderName, int mode, SecretKey sKey,
            GCMParameterSpec ivSpec) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", myProviderName);
        cipher.init(mode, sKey, ivSpec);
        return cipher;
    }

    private static String compressString(String original) {

        return original;
    }

    @Test
    public void testWithOneDataUpdate() throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        byte[] myAAD = "12345678".getBytes();

        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);

        for (int i = 0; i < plainTextStrArray.length; i++) {
            byte[] plainTextBytes = plainTextStrArray[i].getBytes("UTF-8");
            SecretKey key = new SecretKeySpec(new byte[16], "AES"); // key is 16 zero bytes
            byte[] encryptedText = doTestWithOneDataUpdate(Cipher.ENCRYPT_MODE, key, myAAD,
                    plainTextBytes, ivSpec);
            byte[] decryptedText = doTestWithOneDataUpdate(Cipher.DECRYPT_MODE, key, myAAD,
                    encryptedText, ivSpec);
            assertTrue(Arrays.equals(decryptedText, plainTextBytes));
        }
    }

    private byte[] doTestWithOneDataUpdate(int mode, SecretKey sKey, byte[] AAD, byte[] dataText,
            GCMParameterSpec ivSpec) throws Exception {

        // first, generate the cipher text at an allocated buffer

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", getInteropProviderName());
        cipher.init(mode, sKey, ivSpec);
        cipher.updateAAD(AAD);
        byte[] outputText = cipher.doFinal(dataText);

        // new cipher for encrypt operation
        Cipher secondCipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        secondCipher.init(mode, sKey, ivSpec);
        secondCipher.updateAAD(AAD);
        byte[] destText = new byte[secondCipher.getOutputSize(dataText.length)];


        int length = dataText.length / 2;
        // next, generate cipher text again at the same buffer of plain text
        int off = secondCipher.update(dataText, 0, length, destText, 0);
        secondCipher.doFinal(dataText, length, dataText.length - length, destText, off);

        // check if two resutls are equal
        boolean result = java.util.Arrays.equals(destText, outputText);

        if (!result) {
            System.err.println("Two results not equal, mode:" + mode);
            assertTrue(false);
        }

        return destText;
    }

    @Test
    public void testWith1UpdateinPlace2() throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        byte[] myAAD = "12345678".getBytes();

        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);

        for (int i = 0; i < plainTextStrArray.length; i++) {
            byte[] plainTextBytes = plainTextStrArray[i].getBytes("UTF-8");
            SecretKey key = new SecretKeySpec(new byte[16], "AES"); // key is 16 zero bytes
            byte[] encryptedText = doTestWith1UpdateinPlace(Cipher.ENCRYPT_MODE, key, myAAD,
                    plainTextBytes, ivSpec);
            byte[] decryptedText = doTestWith1UpdateinPlace(Cipher.DECRYPT_MODE, key, myAAD,
                    encryptedText, ivSpec);
            assertTrue(Arrays.equals(decryptedText, plainTextBytes));
        }
    }

    public byte[] doTestWith1UpdateinPlace(int mode, SecretKey sKey, byte[] AAD, byte[] input,
            GCMParameterSpec ivSpec) throws Exception {
        //Copy the input into a local byte array which can be updated by cipherUpdate
        int outLength = 0;
        if (mode == Cipher.ENCRYPT_MODE) {
            outLength = input.length + 16;

        } else {
            outLength = input.length;
        }
        byte[] copyOfInput = new byte[outLength];
        System.arraycopy(input, 0, copyOfInput, 0, input.length);

        // first, generate the cipher text at an allocated buffer
        Cipher cipher = createCipher(getInteropProviderName(), mode, sKey, ivSpec);
        cipher.updateAAD(AAD);
        byte[] outputText = cipher.doFinal(copyOfInput, 0, input.length);
        // new cipher for encrypt operation
        Cipher anotherCipher = createCipher(getProviderName(), mode, sKey, ivSpec);
        anotherCipher.updateAAD(AAD);

        // next, generate cipher text again at the same buffer of plain text

        int off = anotherCipher.update(copyOfInput, 0, input.length, copyOfInput, 0);
        anotherCipher.doFinal(copyOfInput, off);

        byte[] copyOfOutput = new byte[outputText.length];
        System.arraycopy(copyOfInput, 0, copyOfOutput, 0, outputText.length);



        // check if two resutls are equal
        boolean result = java.util.Arrays.equals(copyOfOutput, outputText);

        if (!result) {
            System.err.println(
                    "==========doTestWith1UpdateinPlace Two results not equal, mode:" + mode);
            assertTrue(false);
        }

        return copyOfOutput;
    }

    @Test
    public void testWithMultipleDataUpdate() throws Exception {
        byte[] myAAD = "12345678".getBytes();
        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);


        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);


        for (int j = 0; j < plainTextStrArray1.length; j++) {
            int numTimes = (j == 0) ? 2 : 5;
            byte[] plainTextBytes = plainTextStrArray1[j].getBytes("UTF-8");
            SecretKey key = new SecretKeySpec(new byte[16], "AES"); // key is 16 zero bytes
            byte[] encryptedText = doTestWithMultipleDataUpdate(Cipher.ENCRYPT_MODE, key, myAAD,
                    plainTextBytes, ivSpec, numTimes);
            byte[] decryptedText = doTestWithMultipleDataUpdate(Cipher.DECRYPT_MODE, key, myAAD,
                    encryptedText, ivSpec, numTimes);
            assertTrue(Arrays.equals(decryptedText, plainTextBytes));
        }
    }

    private byte[] doTestWithMultipleDataUpdate(int mode, SecretKey sKey, byte[] AAD, byte[] text,
            GCMParameterSpec ivSpec, int numUpdTimes) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", getInteropProviderName());
        cipher.init(mode, sKey, ivSpec);
        cipher.updateAAD(AAD);
        byte[] outputText = cipher.doFinal(text);

        // new cipher for encrypt operation
        Cipher secondCipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        secondCipher.init(mode, sKey, ivSpec);
        secondCipher.updateAAD(AAD);
        byte[] destText = new byte[outputText.length];


        int blocklength = 32;
        int total_offset = 0;

        for (int j = 0; j < numUpdTimes; j++) {
            // next, generate cipher text again at the same buffer of plain text
            int off = secondCipher.update(text, j * blocklength, blocklength, destText,
                    total_offset);
            total_offset = total_offset + off;
        }
        //call doFinal
        secondCipher.doFinal(text, (blocklength * numUpdTimes),
                text.length - (blocklength * numUpdTimes), destText, total_offset);

        // check if two resutls are equal
        boolean result = java.util.Arrays.equals(destText, outputText);

        if (!result) {
            System.err.println(
                    "==========doTestWithMultipleDataUpdate  Two results not equal, mode:" + mode);
            assertTrue(false);
        }


        return destText;
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null)
            return new String("-null-");
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
