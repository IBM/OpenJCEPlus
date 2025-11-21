/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.lang.reflect.Method;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestAESGCMLong extends BaseTestJunit5 {
    private final static int GCM_IV_LENGTH = 12;
    private final static int GCM_TAG_LENGTH = 16;
    private static int ARRAY_OFFSET = 16;
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();


    protected KeyGenerator aesKeyGen;
    protected AlgorithmParameters params = null;
    protected Method methodCipherUpdateAAD = null;

    private Cipher createCipher(int mode, SecretKey sKey, GCMParameterSpec ivSpec)
            throws Exception {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        cipher.init(mode, sKey, ivSpec);
        return cipher;
    }

    @Test
    public void testWith128Times8() throws Exception {

        //Create a 1K string
        int NUMTIMES = 10;
        String kStr = "";
        for (int j = 0; j < 128; j++) {
            kStr = kStr + "01234567";
        }
        byte[] plainBytes = kStr.getBytes("UTF-8");

        for (int keysizeloop = 1; keysizeloop < 3; keysizeloop++) {

            byte[] iv = new byte[GCM_IV_LENGTH];
            (new SecureRandom()).nextBytes(iv);
            byte[] myAAD = "aaaaaaaaa".getBytes();

            GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);

            SecretKey key = new SecretKeySpec(new byte[16 * keysizeloop], "AES");
            byte[] encryptedBytes1 = doTestWithMultipleDataUpdateEncrypt(Cipher.ENCRYPT_MODE, key,
                    myAAD, plainBytes, ivSpec, NUMTIMES, false);
            byte[] recoveredBytes1 = doTestWithMultipleDataUpdateDecrypt(Cipher.DECRYPT_MODE, key,
                    myAAD, encryptedBytes1, ivSpec, NUMTIMES, true);
            byte[] largeByteBuffer = new byte[plainBytes.length * NUMTIMES];
            for (int j = 0; j < 10; j++) {
                System.arraycopy(plainBytes, 0, largeByteBuffer, j * plainBytes.length,
                        plainBytes.length);
            }

            boolean result = java.util.Arrays.equals(recoveredBytes1, largeByteBuffer);
            if (!result) {
                assertTrue(false);
            }
            byte[] encryptedBytes2 = doTestWithMultipleDataUpdateEncrypt(Cipher.ENCRYPT_MODE, key,
                    myAAD, plainBytes, ivSpec, 10, true);
            byte[] recoveredBytes2 = doTestWithMultipleDataUpdateDecrypt(Cipher.DECRYPT_MODE, key,
                    myAAD, encryptedBytes2, ivSpec, 10, true);
            result = java.util.Arrays.equals(recoveredBytes2, largeByteBuffer);
            if (!result) {
                assertTrue(false);
            }

        }
    }

    @Test
    public void testWith128Times7() throws Exception {

        //Create a 1K string
        int NUMTIMES = 10;
        String kStr = "";
        for (int j = 0; j < 127; j++) {
            kStr = kStr + "01234567";
        }
        byte[] plainBytes = kStr.getBytes("UTF-8");

        for (int keysizeloop = 1; keysizeloop < 3; keysizeloop++) {

            byte[] iv = new byte[GCM_IV_LENGTH];
            (new SecureRandom()).nextBytes(iv);
            byte[] myAAD = "aaaaaaaaa".getBytes();

            GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);

            SecretKey key = new SecretKeySpec(new byte[16 * keysizeloop], "AES");
            byte[] encryptedBytes1 = doTestWithMultipleDataUpdateEncrypt(Cipher.ENCRYPT_MODE, key,
                    myAAD, plainBytes, ivSpec, NUMTIMES, false);
            byte[] recoveredBytes1 = doTestWithMultipleDataUpdateDecrypt(Cipher.DECRYPT_MODE, key,
                    myAAD, encryptedBytes1, ivSpec, NUMTIMES, true);
            byte[] largeByteBuffer = new byte[plainBytes.length * NUMTIMES];
            for (int j = 0; j < 10; j++) {
                System.arraycopy(plainBytes, 0, largeByteBuffer, j * plainBytes.length,
                        plainBytes.length);
            }

            boolean result = java.util.Arrays.equals(recoveredBytes1, largeByteBuffer);
            if (!result) {
                assertTrue(false);
            }
            byte[] encryptedBytes2 = doTestWithMultipleDataUpdateEncrypt(Cipher.ENCRYPT_MODE, key,
                    myAAD, plainBytes, ivSpec, 10, true);
            byte[] recoveredBytes2 = doTestWithMultipleDataUpdateDecrypt(Cipher.DECRYPT_MODE, key,
                    myAAD, encryptedBytes2, ivSpec, 10, true);
            result = java.util.Arrays.equals(recoveredBytes2, largeByteBuffer);
            if (!result) {
                assertTrue(false);
            }

        }
    }

    private byte[] doTestWithMultipleDataUpdateEncrypt(int mode, SecretKey sKey, byte[] AAD,
            byte[] dataBytes, GCMParameterSpec ivSpec, int numUpdTimes, boolean noDataForFinal)
            throws Exception {

        byte[] largeByteBuffer = new byte[dataBytes.length * numUpdTimes];
        for (int j = 0; j < numUpdTimes; j++) {
            System.arraycopy(dataBytes, 0, largeByteBuffer, j * dataBytes.length, dataBytes.length);
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        cipher.init(mode, sKey, ivSpec);
        cipher.updateAAD(AAD);
        byte[] outputBytes = cipher.doFinal(largeByteBuffer);

        // new cipher for encrypt operation
        Cipher cipher2 = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        cipher2.init(mode, sKey, ivSpec);
        cipher2.updateAAD(AAD);
        int outputLength = cipher2.getOutputSize(10 * dataBytes.length);
        byte[] destBytes = new byte[outputLength];
        int total_offset = 0;
        int off = 0;
        int numTimes = (noDataForFinal) ? numUpdTimes : (numUpdTimes - 1);

        for (int j = 0; j < numTimes; j++) {
            off = cipher2.update(dataBytes, 0, dataBytes.length, destBytes, total_offset);
            total_offset = total_offset + off;
        }
        //call doFinal
        if (!noDataForFinal) {
            cipher2.doFinal(dataBytes, 0, dataBytes.length, destBytes, total_offset);
        } else {
            cipher2.doFinal(dataBytes, 0, 0, destBytes, total_offset);
        }

        boolean result = java.util.Arrays.equals(destBytes, outputBytes);

        if (!result) {
            assertTrue(false);
        }

        return outputBytes;

    }

    private byte[] doTestWithMultipleDataUpdateDecrypt(int mode, SecretKey sKey, byte[] AAD,
            byte[] largeByteBuffer, GCMParameterSpec ivSpec, int numUpdTimes,
            boolean noDataForFinal) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        cipher.init(mode, sKey, ivSpec);
        cipher.updateAAD(AAD);
        byte[] outputBytes = cipher.doFinal(largeByteBuffer);

        // new cipher for encrypt operation
        Cipher cipher2 = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        cipher2.init(mode, sKey, ivSpec);
        cipher2.updateAAD(AAD);

        int outputLength = cipher2.getOutputSize(largeByteBuffer.length);
        byte[] destBytes = new byte[outputLength];
        int total_offset = 0;
        int off = 0;

        for (int j = 0; j < numUpdTimes - 1; j++) {
            off = cipher2.update(largeByteBuffer, j * 1024, 1024, destBytes, total_offset);
            total_offset = total_offset + off;
        }
        //call doFinal
        if (!noDataForFinal) {
            int lastDataBlock = largeByteBuffer.length - ((numUpdTimes - 1) * 1024);
            cipher2.doFinal(largeByteBuffer, largeByteBuffer.length - lastDataBlock, lastDataBlock,
                    destBytes, total_offset);
        } else {
            int lastDataBlock = largeByteBuffer.length - ((numUpdTimes - 1) * 1024);
            off = cipher2.update(largeByteBuffer, largeByteBuffer.length - lastDataBlock,
                    lastDataBlock, destBytes, total_offset);
            total_offset = total_offset + off;
            cipher2.doFinal(largeByteBuffer, largeByteBuffer.length, 0, destBytes, total_offset);
        }

        boolean result = java.util.Arrays.equals(destBytes, outputBytes);

        if (!result) {
            assertTrue(false);
        }

        return outputBytes;

    }
}
