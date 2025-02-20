/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestAESGCMUpdate extends BaseTestJunit5 {
    private final static int GCM_IV_LENGTH = 12;
    private final static int GCM_TAG_LENGTH = 16;
    private static int ARRAY_OFFSET = 16;
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    protected KeyGenerator aesKeyGen;
    protected AlgorithmParameters params = null;
    protected Method methodCipherUpdateAAD = null;
    protected int specifiedKeySize = 0;

    static final byte[] plainText14 = "12345678123456".getBytes();

    // 16 bytes: PASSED
    static final byte[] plainText16 = "1234567812345678".getBytes();

    // 18 bytes: PASSED
    static final byte[] plainText18 = "123456781234567812".getBytes();

    // 63 bytes: PASSED
    static final byte[] plainText63 = "123456781234567812345678123456781234567812345678123456781234567"
            .getBytes();

    // 128 bytes: PASSED
    static final byte[] plainText128 = "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
            .getBytes();
    protected SecretKey key;
    byte[] ivBytes = "123456".getBytes();
    byte[] aadBytes = new byte[16];

    @BeforeEach
    public void setUp() throws Exception {
        aesKeyGen = KeyGenerator.getInstance("AES", getProviderName());
        if (specifiedKeySize > 0) {
            aesKeyGen.init(specifiedKeySize);
        }
        key = aesKeyGen.generateKey();
    }

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


    private Cipher createCipher(int mode, SecretKey sKey, GCMParameterSpec ivSpec)
            throws Exception {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        cipher.init(mode, sKey, ivSpec);
        return cipher;
    }

    private static String compressString(String original) {

        return original;
        /*
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < original.length(); i++) {
            String character = original.substring(i, i + 1);
            if (output.indexOf(character) < 0) // if not contained
                output.append(character);
        }
        return output.toString();*/
    }

    @Disabled
    public void testNoDataUpdate1(String dataStr, SecretKey skey) throws Exception {
        for (int keysizeloop = 1; keysizeloop < 3; keysizeloop++) {


            SecretKey key = new SecretKeySpec(new byte[16 * keysizeloop], "AES"); // key is 16 zero bytes

            for (int i = 0; i < plainTextStrArray.length; i++) {

                String s = doDecryptNoDataUpdate(doEncryptNoDataUpdate(plainTextStrArray[i], key),
                        key);
                assertTrue(s.equals(plainTextStrArray[i]));

            }


        }
    }

    private String doEncryptNoDataUpdate(String privateString, SecretKey skey) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, skey, ivSpec);
        cipher.updateAAD("12345678".getBytes());

        byte[] ciphertext = cipher.doFinal(privateString.getBytes("UTF8"));
        byte[] encrypted = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encrypted, 0, iv.length);
        System.arraycopy(ciphertext, 0, encrypted, iv.length, ciphertext.length);

        String encoded = Base64.getEncoder().encodeToString(encrypted);

        return encoded;
    }

    private String doDecryptNoDataUpdate(String encrypted, SecretKey skey) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(encrypted);

        byte[] iv = Arrays.copyOfRange(decoded, 0, GCM_IV_LENGTH);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
        cipher.init(Cipher.DECRYPT_MODE, skey, ivSpec);
        cipher.updateAAD("12345678".getBytes());

        byte[] plaintext = cipher.doFinal(decoded, GCM_IV_LENGTH, decoded.length - GCM_IV_LENGTH);

        String result = new String(plaintext, "UTF8");

        return result;
    }

    @Test
    public void testCaseWithLongString2() throws Exception {

        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        byte[] myAAD = "aaaaaaaaa".getBytes();

        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);

        for (int keysizeloop = 1; keysizeloop < 3; keysizeloop++) {
            StringBuilder myStr = new StringBuilder();
            SecretKey key16 = new SecretKeySpec(new byte[16 * keysizeloop], "AES"); // key is 16 zero bytes

            for (int i = 0; i < 118999;) {
                myStr.append("a");

                byte[] plainTextBytes = myStr.toString().getBytes(StandardCharsets.UTF_8);

                byte[] encryptedText = dotestWithString(Cipher.ENCRYPT_MODE, key16, myAAD,
                        plainTextBytes, ivSpec);
                byte[] decryptedText = dotestWithString(Cipher.DECRYPT_MODE, key16, myAAD,
                        encryptedText, ivSpec);
                assertTrue(Arrays.equals(decryptedText, plainTextBytes));
                i = i + 23;

            }

            System.out.println("dotestCaseWithLongString = " + myStr.length());
        }
    }

    @Test
    public void testCaseWithShorString3() throws Exception {

        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        byte[] myAAD = "12345678".getBytes();

        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
        for (int keysizeloop = 1; keysizeloop < 3; keysizeloop++) {
            for (int i = 0; i < plainTextStrArray.length; i++) {

                byte[] plainTextBytes = plainTextStrArray[i].getBytes("UTF-8");


                SecretKey key = new SecretKeySpec(new byte[16 * keysizeloop], "AES"); // key is 16 or 32 bit zero bytes
                byte[] encryptedText = dotestWithString(Cipher.ENCRYPT_MODE, key, myAAD,
                        plainTextBytes, ivSpec);
                byte[] decryptedText = dotestWithString(Cipher.DECRYPT_MODE, key, myAAD,
                        encryptedText, ivSpec);
                assertTrue(Arrays.equals(decryptedText, plainTextBytes));

            }
        }

    }

    private byte[] dotestWithString(int mode, SecretKey sKey, byte[] AAD, byte[] plainText,
            GCMParameterSpec ivSpec) throws Exception {
        Cipher ci = createCipher(mode, sKey, ivSpec);
        ci.updateAAD(AAD);
        byte[] part31 = new byte[ci.getOutputSize(plainText.length)];
        int offset = (plainText.length > 32) ? 32 : 0;
        int len = ci.update(plainText, 0, plainText.length - offset, part31, 0);
        byte[] part32 = ci.doFinal(plainText, plainText.length - offset, offset);
        byte[] outputText3 = new byte[len + part32.length];
        System.arraycopy(part31, 0, outputText3, 0, len);
        System.arraycopy(part32, 0, outputText3, len, part32.length);
        return (outputText3);
    }

    @Test
    public void testCaseShortBufferError4() throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        byte[] myAAD = "12345678".getBytes();

        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
        for (int keysizeloop = 1; keysizeloop < 3; keysizeloop++) {
            for (int i = 0; i < plainTextStrArray.length; i++) {

                byte[] plainTextBytes = plainTextStrArray[i].getBytes("UTF-8");
                //System.out.println ("String to encrypt/Decrypt= " +  plainTextStrArray[i]);
                try {

                    SecretKey key = new SecretKeySpec(new byte[16 * keysizeloop], "AES"); // key is 16 zero bytes
                    dotestCaseShortBuffer(Cipher.ENCRYPT_MODE, key, myAAD,
                            plainTextBytes, ivSpec);
                    byte[] encryptedText1 = dotestWithString(Cipher.ENCRYPT_MODE, key, myAAD,
                            plainTextBytes, ivSpec);
                    //System.out.println ("encryptedText1 = " + encryptedText1);
                    byte[] decryptedText = dotestCaseShortBuffer(Cipher.DECRYPT_MODE, key, myAAD,
                            encryptedText1, ivSpec);
                    //System.out.println ("decryptedText = " + decryptedText);

                    assertTrue(Arrays.equals(decryptedText, plainTextBytes));
                }

                catch (ShortBufferException sxe) {
                    assertTrue(true);
                } catch (Exception ex) {
                    ex.printStackTrace();
                    assertTrue(false);
                }
            }

        }


    }

    private byte[] dotestCaseShortBuffer(int mode, SecretKey sKey, byte[] AAD, byte[] dataText,
            GCMParameterSpec ivSpec) throws Exception {

        try {
            Cipher ci = createCipher(mode, sKey, ivSpec);
            ci.updateAAD(AAD);

            int offset = (dataText.length > 32) ? 32 : 0;
            byte[] part31 = new byte[4]; //new byte[ci.getOutputSize(plainText.length) - 1];
            //System.out.println( "=====testCaseShortBuffer plainText.length  " + plainText.length + " parts31.length " +  part31.length);
            int len = ci.update(dataText, 0, dataText.length - offset, part31, 0);
            byte[] part32 = ci.doFinal(dataText, dataText.length - offset, offset);
            byte[] outputText3 = new byte[len + part32.length];
            System.arraycopy(part31, 0, outputText3, 0, len);
            System.arraycopy(part32, 0, outputText3, len, part32.length);
            return outputText3;

        } catch (ShortBufferException sbe) {

            throw sbe;
        } catch (Exception ex) {
            System.err.println("Unexpected exception ");
            assertTrue(false);
            return (byte[]) null;


        }
    }

    @Test
    public void testCaseCallAfterShortBuffer5() throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        byte[] myAAD = "12345678".getBytes();

        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
        for (int keysizeloop = 1; keysizeloop < 3; keysizeloop++) {
            for (int i = 0; i < plainTextStrArray.length; i++) {

                byte[] plainTextBytes = plainTextStrArray[i].getBytes("UTF-8");
                //System.out.println ("String to encrypt/Decrypt= " +  plainTextStrArray[i]);
                try {

                    SecretKey key = new SecretKeySpec(new byte[16 * keysizeloop], "AES"); // key is 16 zero bytes
                    byte[] encryptedText = dotestCaseCallAfterShortBuffer(Cipher.ENCRYPT_MODE, key,
                            myAAD, plainTextBytes, ivSpec);

                    //System.out.println ("encryptedText1 = " + encryptedText1);
                    byte[] decryptedText = dotestCaseCallAfterShortBuffer(Cipher.DECRYPT_MODE, key,
                            myAAD, encryptedText, ivSpec);
                    //System.out.println ("decryptedText = " + decryptedText);

                    assertTrue(Arrays.equals(decryptedText, plainTextBytes));
                } catch (ShortBufferException sxe) {
                    assertTrue(true);
                } catch (Exception ex) {
                    ex.printStackTrace();
                    assertTrue(false);
                }
            }

        }


    }

    private byte[] dotestCaseCallAfterShortBuffer(int mode, SecretKey sKey, byte[] AAD,
            byte[] dataText, GCMParameterSpec ivSpec) throws Exception {
        int len = 0;
        try {
            Cipher ci = createCipher(mode, sKey, ivSpec);
            ci.updateAAD(AAD);

            int offset = (dataText.length > 32) ? 32 : 0;
            byte[] part31 = new byte[4]; //new byte[ci.getOutputSize(plainText.length) - 1];

            //System.out.println( "=====testCaseShortBuffer plainText.length  " + plainText.length + " parts31.length " +  part31.length);
            try {
                len = ci.update(dataText, 0, dataText.length - offset, part31, 0);
            } catch (ShortBufferException sbe) {
                part31 = new byte[ci.getOutputSize(dataText.length)];
                len = ci.update(dataText, 0, dataText.length - offset, part31, 0);

            }

            byte[] part32 = ci.doFinal(dataText, dataText.length - offset, offset);
            byte[] outputText3 = new byte[len + part32.length];
            System.arraycopy(part31, 0, outputText3, 0, len);
            System.arraycopy(part32, 0, outputText3, len, part32.length);
            return outputText3;

        } catch (Exception ex) {
            ex.printStackTrace();
            System.err.println("Unexpected exception " + ex.getMessage());
            assertTrue(false);
            return (byte[]) null;


        }
    }

    @Test
    public void testCaseCallUpdateAfterFinal() throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        byte[] myAAD = "12345678".getBytes();

        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);

        for (int i = 0; i < plainTextStrArray.length; i++) {

            byte[] plainTextBytes = plainTextStrArray[i].getBytes("UTF-8");
            byte[] encryptedText = null;
            //System.out.println ("String to encrypt/Decrypt= " +  plainTextStrArray[i]);
            try {

                SecretKey key = new SecretKeySpec(new byte[16], "AES"); // key is 16 zero bytes
                encryptedText = doCallUpdateAfterFinal(Cipher.ENCRYPT_MODE, key, myAAD,
                        plainTextBytes, ivSpec);
                assertTrue(false);
            } catch (IllegalStateException ex) {
                //ex.printStackTrace();
                assertTrue(true);
            }

            catch (Exception ex) {
                ex.printStackTrace();
                assertTrue(false);

            }

            try {
                //System.out.println ("encryptedText1 = " + encryptedText1);
                SecretKey key = new SecretKeySpec(new byte[16], "AES"); // key is 16 zero bytes
                encryptedText = dotestWithString(Cipher.ENCRYPT_MODE, key, myAAD, plainTextBytes,
                        ivSpec);
                doCallUpdateAfterFinal(Cipher.DECRYPT_MODE, key, myAAD,
                        encryptedText, ivSpec);
                //System.out.println ("decryptedText = " + decryptedText);
            } catch (IllegalStateException ex) {
                //ex.printStackTrace();
                assertTrue(true);
            } catch (Exception ex) {
                ex.printStackTrace();
                assertTrue(false);
            }


        }



    }



    private byte[] doCallUpdateAfterFinal(int mode, SecretKey sKey, byte[] AAD, byte[] dataText,
            GCMParameterSpec ivSpec) throws Exception {
        int len = 0;

        Cipher ci = createCipher(mode, sKey, ivSpec);
        ci.updateAAD(AAD);

        int offset = (dataText.length > 32) ? 32 : 0;
        byte[] part31_a = new byte[ci.getOutputSize(dataText.length)];
        byte[] part31_b = new byte[ci.getOutputSize(dataText.length)];



        //System.out.println( "=====testCaseShortBuffer plainText.length  " + plainText.length + " parts31.length " +  part31.length);

        len = ci.update(dataText, 0, dataText.length - offset, part31_a, 0);


        byte[] part32_a = ci.doFinal(dataText, dataText.length - offset, offset);
        byte[] outputText_a = new byte[len + part32_a.length];
        System.arraycopy(part31_a, 0, outputText_a, 0, len);
        System.arraycopy(part32_a, 0, outputText_a, len, part32_a.length);

        ci.update(dataText, 0, dataText.length - offset, part31_b, 0);
        //byte[] part32_b = ci.doFinal(dataText, dataText.length - offset,
        //        offset);
        //            byte[] outputText_b = new byte[len + part32_a.length];
        //            System.arraycopy(part31_b, 0, outputText_b, 0, len_b);
        //            System.arraycopy(part32_b, 0, outputText_b, len, part32_b.length);

        return outputText_a;
    }

    /** create a plaintext of 26*99 and write it to a plain file.
     * read the plain file and encrypt it and write it to encrypted file
     * read the encrypted file and decrypt it and write the decrypted bytes to a decrypted file
     * read both the plain and decrypted files and verify they are same.
     */
    @Test
    public void testReadWriteToAFile6() throws Exception {

        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        byte[] myAAD = "12345678".getBytes();

        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);

        for (int i = 0; i < plainTextStrArray.length; i++) {
            SecretKey key = new SecretKeySpec(new byte[16], "AES"); // key is 16 zero bytes
            doTestReadWriteToAFile(i, key, myAAD, plainTextStrArray[i], ivSpec);
        }
    }

    private void doTestReadWriteToAFile(int fileCount, SecretKey sKey, byte[] AAD, String dataStr,
            GCMParameterSpec ivSpec) throws GeneralSecurityException, IOException, Exception {

        Thread t = Thread.currentThread();
        long threadId = t.getId();
        String fileNamePlain = "." + File.separator + fileCount + "TestAESGCM_P_" + threadId
                + ".txt";
        String fileNameEncrypted = "." + File.separator + fileCount + "TestAESGCM_E_" + threadId
                + ".txt";
        String fileNameDecrypted = "." + File.separator + fileCount + "TestAESGCM_D_" + threadId
                + ".txt";

        int BUFFER_SIZE_ENCRYPTING = 128;
        int BUFFER_SIZE_DECRYPTING = 64;
        int lenPlain = 0;
        int lenEncrypted = 0;

        FileOutputStream fosPlain = null;
        DataOutputStream outStreamPlain = null;
        FileInputStream fisPlain = null;
        DataInputStream inputStreamPlain = null;
        FileOutputStream fosEncrypted = null;
        DataOutputStream outStreamEncrypted = null;

        DataInputStream inputStreamEncrypted = null;
        FileInputStream fisEncrypted = null;


        FileOutputStream fosDecrypted = null;
        DataOutputStream outStreamDecrypted = null;
        FileInputStream fisPlainVerify = null;
        DataInputStream inputStreamPlainVerify = null;

        FileInputStream fisDecryptedVerify = null;
        DataInputStream inputStreamDecryptedVerify = null;


        try {
            fosPlain = new FileOutputStream(fileNamePlain);
            outStreamPlain = new DataOutputStream(new BufferedOutputStream(fosPlain));

            for (int i = 0; i < 99; i++) {
                outStreamPlain.writeUTF(dataStr);
            }
            outStreamPlain.close();

            //Read the plain text and ecnrypt it and write it out to a encryptedFile
            fisPlain = new FileInputStream(fileNamePlain);
            inputStreamPlain = new DataInputStream(new BufferedInputStream(fisPlain));

            fosEncrypted = new FileOutputStream(fileNameEncrypted);
            outStreamEncrypted = new DataOutputStream(new BufferedOutputStream(fosEncrypted));

            Cipher cipherE = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cipherE.init(Cipher.ENCRYPT_MODE, sKey, ivSpec);
            cipherE.updateAAD(AAD);
            byte[] bufferE = new byte[BUFFER_SIZE_ENCRYPTING];
            while ((lenPlain = inputStreamPlain.read(bufferE, 0, bufferE.length)) != -1) {
                byte[] encrypted = cipherE.update(bufferE, 0, lenPlain);
                outStreamEncrypted.write(encrypted);
            }
            byte[] finalBlk = cipherE.doFinal();
            if (finalBlk.length > 0) {
                outStreamEncrypted.write(finalBlk);
            }
            outStreamEncrypted.close();
            inputStreamPlain.close();


            Cipher cipherD = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cipherD.init(Cipher.DECRYPT_MODE, sKey, ivSpec);
            cipherD.updateAAD(AAD);

            //Read the encryted text and decrypt it and write it out to a decrypedFile
            fisEncrypted = new FileInputStream(fileNameEncrypted);
            inputStreamEncrypted = new DataInputStream(new BufferedInputStream(fisEncrypted));



            fosDecrypted = new FileOutputStream(fileNameDecrypted);
            outStreamDecrypted = new DataOutputStream(new BufferedOutputStream(fosDecrypted));

            byte[] bufferD = new byte[BUFFER_SIZE_DECRYPTING];
            while ((lenEncrypted = inputStreamEncrypted.read(bufferD, 0, bufferD.length)) != -1) {
                byte[] decrypted = cipherD.update(bufferD, 0, lenEncrypted);
                outStreamDecrypted.write(decrypted);
            }
            byte[] finalBlkDecrypted = cipherD.doFinal();
            if (finalBlkDecrypted.length > 0) {
                outStreamDecrypted.write(finalBlkDecrypted);
            }
            outStreamPlain.close();
            outStreamDecrypted.close();
            inputStreamEncrypted.close();

            //verify both the plain text file and decrypted file are identical
            fisPlainVerify = new FileInputStream(fileNamePlain);
            inputStreamPlainVerify = new DataInputStream(new BufferedInputStream(fisPlainVerify));

            fisDecryptedVerify = new FileInputStream(fileNameDecrypted);
            inputStreamDecryptedVerify = new DataInputStream(
                    new BufferedInputStream(fisDecryptedVerify));



            String resultPlain = inputStreamPlainVerify.readUTF();
            String resultDecryped = inputStreamDecryptedVerify.readUTF();

            inputStreamDecryptedVerify.close();
            inputStreamPlainVerify.close();

            if (!resultPlain.equals(resultDecryped)) {
                System.out.println("resultPlain does not match resultDecrypted");
                assertTrue(false);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            outStreamPlain.close();

            inputStreamPlain.close();
            outStreamEncrypted.close();
            inputStreamEncrypted.close();
            outStreamDecrypted.close();


            inputStreamDecryptedVerify.close();
            inputStreamPlainVerify.close();



            Files.deleteIfExists(Paths.get(fileNamePlain));
            Files.deleteIfExists(Paths.get(fileNameEncrypted));
            Files.deleteIfExists(Paths.get(fileNameDecrypted));
        }


    }

    @Test
    public void testWithOneDataUpdate7() throws Exception {
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

        // String modeStr = (mode == Cipher.ENCRYPT_MODE) ? "Encrypting ":"Decrypting";
        //System.out.println ("====== doTestWithOneUpdate Entering " + modeStr + "dataText.length=" +  dataText.length);
        // first, generate the cipher text at an allocated buffer

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        cipher.init(mode, sKey, ivSpec);
        cipher.updateAAD(AAD);
        byte[] outputText = cipher.doFinal(dataText);

        // new cipher for encrypt operation
        Cipher secondCipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        secondCipher.init(mode, sKey, ivSpec);
        secondCipher.updateAAD(AAD);
        byte[] destText = new byte[secondCipher.getOutputSize(dataText.length)];
        //System.out.println ("===== doTestWithOneUpdate destText length " + destText.length);


        int length = dataText.length / 2;
        // next, generate cipher text again at the same buffer of plain text
        //System.out.println ("===== doTestWithOneUpdate Calling secondCipher.Update length " + length);
        int off = secondCipher.update(dataText, 0, length, destText, 0);
        //System.out.println ("===== doTestWithOneUpdate Off set after first update " + off);
        //System.out.println ("===== doTestWithOneUpdate Calling dofinal " + (dataText.length - length));
        secondCipher.doFinal(dataText, length, dataText.length - length, destText, off);

        // check if two resutls are equal
        boolean result = java.util.Arrays.equals(destText, outputText);

        if (!result) {
            System.err.println("Two results not equal, mode:" + mode);
            assertTrue(false);
        }

        //System.out.println ("====== doTestWithOneUpdate exiting " + modeStr + "outputText size = " + outputText.length + " output = " + bytesToHex(outputText));
        return destText;
    }

    @Test
    public void testWith1UpdateinPlace8() throws Exception {
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
        // String modeStr = (mode == Cipher.ENCRYPT_MODE)?"Encrypting ": "Decrypting ";
        //System.out.println ("======doTestWithOneUpdate Entering " + modeStr + "input.length=" +  input.length);
        //Copy the input into a local byte array which can be updated by cipherUpdate
        int outLength = 0;
        if (mode == Cipher.ENCRYPT_MODE) {
            outLength = input.length + 16;

        } else {
            outLength = input.length;
        }
        //System.out.println ("==========doTestWith1UpdateinPlace outLength=" + outLength);
        byte[] copyOfInput = new byte[outLength];
        System.arraycopy(input, 0, copyOfInput, 0, input.length);

        // first, generate the cipher text at an allocated buffer
        Cipher cipher = createCipher(mode, sKey, ivSpec);
        cipher.updateAAD(AAD);
        byte[] outputText = cipher.doFinal(copyOfInput, 0, input.length);
        //System.out.println ("==========doTestWith1UpdateinPlace no updates = outputText" + outputText.length);
        // new cipher for encrypt operation
        Cipher anotherCipher = createCipher(mode, sKey, ivSpec);
        anotherCipher.updateAAD(AAD);

        // next, generate cipher text again at the same buffer of plain text

        int off = anotherCipher.update(copyOfInput, 0, input.length, copyOfInput, 0);
        //System.out.println ("==========doTestWith1UpdateinPlace output from anotherCipher.update = " + off);
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

        //System.out.println ("==========doTestWith1UpdateinPlace Exiting.. copyOfOutput.length=" + copyOfOutput.length);
        return copyOfOutput;
    }

    @Test
    public void testWithMultipleDataUpdate9() throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        byte[] myAAD = "12345678".getBytes();

        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
        for (int keysizeloop = 1; keysizeloop < 3; keysizeloop++) {
            StringBuilder myStr = new StringBuilder();
            for (int i = 0; i < 250; i++) {
                myStr.append("a");
            }
            for (int i = 250; i < 118999;) {
                myStr.append("a");
                int numTimes = 7;
                byte[] plainTextBytes = myStr.toString().getBytes(StandardCharsets.UTF_8);
                SecretKey key = new SecretKeySpec(new byte[16 * keysizeloop], "AES"); // key is 16 zero bytes
                byte[] encryptedText = doTestWithMultipleDataUpdate(Cipher.ENCRYPT_MODE, key, myAAD,
                        plainTextBytes, ivSpec, numTimes);
                byte[] decryptedText = doTestWithMultipleDataUpdate(Cipher.DECRYPT_MODE, key, myAAD,
                        encryptedText, ivSpec, numTimes);
                assertTrue(Arrays.equals(decryptedText, plainTextBytes));
                i = i + 17;
            }
        }
    }

    @Test
    public void testWithMultipleDataUpdate10() throws Exception {
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

        // String modeStr = (mode == Cipher.ENCRYPT_MODE) ? "Encrypting ":"Decrypting";
        // first, generate the cipher text at an allocated buffer
        //System.out.println ("================doTestWithMultipleDataUpdate mode = " + modeStr);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        cipher.init(mode, sKey, ivSpec);
        cipher.updateAAD(AAD);
        byte[] outputText = cipher.doFinal(text);
        //System.out.println ("================doTestWithMultipleDataUpdate outputText.length = " + outputText.length);

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
            //System.out.println ("================doTestWithMultipleDataUpdate j = " + j + " off = " + off);
            total_offset = total_offset + off;
            //System.out.println ("================doTestWithMultipleDataUpdate j = " + j + " total_offset = " + total_offset);
        }
        //call doFinal
        secondCipher.doFinal(text, (blocklength * numUpdTimes),
                text.length - (blocklength * numUpdTimes), destText, total_offset);

        //System.out.println ("Exiting " + modeStr + " " + bytesToHex(destText)); 
        // check if two resutls are equal
        //if (mode == Cipher.DECRYPT_MODE) {
            //System.out.println ("========outputText " + new String (outputText, "UTF8")); 
            //System.out.println ("========destText " + new String(destText, "UTF8")); 
        //}

        boolean result = java.util.Arrays.equals(destText, outputText);

        if (!result) {
            System.err.println(
                    "==========doTestWithMultipleDataUpdate  Two results not equal, mode:" + mode);
            assertTrue(false);
        }


        return destText;
    }

    @Test
    public void testByteBuffer11() throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        byte[] myAAD = "12345678".getBytes();

        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);

        for (int keysizeloop = 1; keysizeloop < 3; keysizeloop++) {
            for (int j = plainTextStrArray.length - 2; j < plainTextStrArray.length; j++) {

                byte[] plainTextBytes = plainTextStrArray[j].getBytes("UTF-8");
                SecretKey key = new SecretKeySpec(new byte[16 * keysizeloop], "AES"); // key is 16 zero bytes
                byte[] encryptedText = doTestByteBuffer(Cipher.ENCRYPT_MODE, key, myAAD,
                        plainTextBytes, ivSpec);
                byte[] decryptedText = doTestByteBuffer(Cipher.DECRYPT_MODE, key, myAAD,
                        encryptedText, ivSpec);
                assertTrue(Arrays.equals(decryptedText, plainTextBytes));
            }
        }
    }

    private byte[] doTestByteBuffer(int mode, SecretKey sKey, byte[] AAD, byte[] plainText,
            GCMParameterSpec ivSpec) throws Exception {

        // prepare ByteBuffer to test
        ByteBuffer buf = ByteBuffer.allocate(AAD.length);
        buf.put(AAD);
        buf.position(0);
        buf.limit(AAD.length);
        Cipher ci = createCipher(mode, sKey, ivSpec);
        ci.updateAAD(buf);

        // prepare an empty ByteBuffer
        ByteBuffer emptyBuf = ByteBuffer.allocate(0);
        emptyBuf.put(new byte[0]);
        ci.updateAAD(emptyBuf);
        byte[] part12_1 = new byte[ci.getOutputSize(plainText.length)];
        int offset = plainText.length > ARRAY_OFFSET ? ARRAY_OFFSET : 0;
        int len12 = ci.update(plainText, 0, plainText.length - offset, part12_1, 0);
        int rest12 = ci.doFinal(plainText, plainText.length - offset, offset, part12_1, len12);
        byte[] outputText12 = new byte[len12 + rest12];
        System.arraycopy(part12_1, 0, outputText12, 0, outputText12.length);
        return (outputText12);
    }

    @Test
    public void test1Update1Final12() throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        byte[] myAAD = "12345678".getBytes();

        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);


        for (int j = plainTextStrArray.length - 2; j < plainTextStrArray.length; j++) {

            byte[] plainTextBytes = plainTextStrArray[j].getBytes("UTF-8");
            SecretKey key = new SecretKeySpec(new byte[16], "AES"); // key is 16 zero bytes
            byte[] encryptedText = doTest1Update1Final(Cipher.ENCRYPT_MODE, key, myAAD,
                    plainTextBytes, ivSpec);
            byte[] decryptedText = doTest1Update1Final(Cipher.DECRYPT_MODE, key, myAAD,
                    encryptedText, ivSpec);
            assertTrue(Arrays.equals(decryptedText, plainTextBytes));
        }
    }

    private byte[] doTest1Update1Final(int mode, SecretKey sKey, byte[] AAD, byte[] dataText,
            GCMParameterSpec ivSpec) throws Exception {

        //System.out.println ("====== AESGCM7 Entering " + modeStr + "dataText.length=" +  dataText.length);

        Cipher ci = createCipher(mode, sKey, ivSpec);
        ci.updateAAD(AAD, 0, AAD.length);
        ci.updateAAD(AAD, AAD.length, 0);
        byte[] part71 = new byte[ci.getOutputSize(dataText.length)];
        //System.out.println ("=======part71 length=" + part71.length);
        int offset = dataText.length > ARRAY_OFFSET ? ARRAY_OFFSET : 0;
        //System.out.println ("=======offset " + offset);
        //System.out.println ("======= arguments to Ci.update= 0 " + "dataText.length=" + dataText.length 
        //+ " (dataText.length - offset) passed = " + (dataText.length - offset) + " " + 0);
        int len = ci.update(dataText, 0, dataText.length - offset, part71, 0);
        //System.out.println ("======== len " + len );
        //System.out.println ("====== part71="+ bytesToHex(part71));
        //System.out.println ("Arguments to doFinal=" + (dataText.length - offset) + " "  + offset);
        byte[] part72 = ci.doFinal(dataText, dataText.length - offset, offset);

        //System.out.println ("=======part72 length=" + part72.length + " parts72=" + bytesToHex(part72));


        byte[] outputText7 = new byte[len + part72.length];
        System.arraycopy(part71, 0, outputText7, 0, len);
        System.arraycopy(part72, 0, outputText7, len, part72.length);
        return (outputText7);
        //System.out.println ("====== AESGCM7 exiting " + modeStr + "output size = " + outputText7.length + " output = " + bytesToHex(outputText7));

    }

    @Test
    public void testCalllAAEDAfterDataUpdate13() throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        byte[] myAAD = "12345678".getBytes();

        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);


        for (int j = plainTextStrArray.length - 2; j < plainTextStrArray.length; j++) {

            byte[] plainTextBytes = plainTextStrArray[j].getBytes("UTF-8");
            SecretKey key = new SecretKeySpec(new byte[16], "AES"); // key is 16 zero bytes
            doTestCallAAEDAfterDataUpdate(Cipher.ENCRYPT_MODE, key, myAAD, plainTextBytes, ivSpec);

            byte[] encryptedText = doTest1Update1Final(Cipher.ENCRYPT_MODE, key, myAAD,
                    plainTextBytes, ivSpec);
            doTestCallAAEDAfterDataUpdate(Cipher.DECRYPT_MODE, key, myAAD, encryptedText, ivSpec);
            //assertTrue (Arrays.equals(decryptedText, plainTextBytes));
        }
    }

    private void doTestCallAAEDAfterDataUpdate(int mode, SecretKey sKey, byte[] AAD,
            byte[] dataText, GCMParameterSpec ivSpec) throws Exception {
        //String modeStr = (mode == Cipher.ENCRYPT_MODE) ? "Encrypting ":"Decrypting";
        //System.out.println ("====== testCallAAEDAfterDataUpdate Entering " + modeStr + "dataText.length=" +  dataText.length);
        try {
            Cipher ci = createCipher(mode, sKey, ivSpec);
            //System.out.println ("=======testCallAAEDAferDataUpdate =  firstCall");
            ci.updateAAD(AAD, 0, AAD.length);
            // System.out.println ("=======testCallAAEDAferDataUpdate =  secondCall");
            ci.updateAAD(AAD, AAD.length, 0);
            byte[] part71 = new byte[ci.getOutputSize(dataText.length)];
            //System.out.println ("=======part71 length=" + part71.length);
            int offset = dataText.length > ARRAY_OFFSET ? ARRAY_OFFSET : 0;
            //System.out.println ("=======offset " + offset);
            //System.out.println ("======= arguments to Ci.update= 0 " + "dataText.length=" + dataText.length 
            //+ " (dataText.length - offset) passed = " + (dataText.length - offset) + " " + 0);
            int len = ci.update(dataText, 0, dataText.length - offset, part71, 0);
            //System.out.println ("======= arguments to 3rd call  Ci.updateAAD = 0 " + "AAD.length=" + AAD.length);
            ci.updateAAD(AAD, 0, AAD.length);
            //System.out.println ("======= arguments to th call  Ci.updateAAD = 0 " + "AAD.length=" + AAD.length);
            ci.updateAAD(AAD, AAD.length, 0);

            //System.out.println ("======== len " + len );
            //System.out.println ("====== part71="+ bytesToHex(part71));
            //System.out.println ("Arguments to doFinal=" + (dataText.length - offset) + " "  + offset);
            byte[] part72 = ci.doFinal(dataText, dataText.length - offset, offset);

            //System.out.println ("=======part72 length=" + part72.length + " parts72=" + bytesToHex(part72));


            byte[] outputText7 = new byte[len + part72.length];
            System.arraycopy(part71, 0, outputText7, 0, len);
            System.arraycopy(part72, 0, outputText7, len, part72.length);

            //System.out.println ("====== testCallAAEDAfterDataUpdate exiting " + modeStr + "output size = " + outputText7.length + " output = " + bytesToHex(outputText7));
        } catch (IllegalStateException ise) {
            //System.out.println ("====== testCallAAEDAfterDataUpdate got the expected Illegal State Exception");
        } catch (Exception ex) {
            //ex.printStackTrace();
            System.err.println("Unexcepted exception=" + ex.getMessage());
            assertTrue(false);
        }
    }

    @Test
    public void testWithUpdatesShortBuffer() throws Exception {
        Cipher cpl = null;
        try {

            cpl = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, ivBytes); //128 bit auth tag length
            cpl.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
            cpl.updateAAD(aadBytes);
            cpl.update(plainText18);
            byte[] cipherText = new byte[5];
            cpl.doFinal(plainText128, 0, plainText128.length, cipherText);
            fail("Expected ShortBufferException did not occur");
        } catch (ShortBufferException ex) {
            byte[] cipherText = new byte[128 + 16 + 16];
            cpl.doFinal(plainText128, 0, plainText128.length, cipherText);
            assertTrue(true);
        }
    }

    @Test
    public void testWithUdpatesEncryptAfterShortBufferRetry() throws Exception {
        Cipher cpl = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, ivBytes); //128 bit auth tag length
        try {
            cpl.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
            cpl.updateAAD(aadBytes);
            cpl.update(plainText18);
            byte[] cipherText = new byte[5];
            cpl.doFinal(plainText128, 0, plainText128.length, cipherText);
            fail("Expected ShortBufferException did not occur");
        } catch (ShortBufferException ex) {
            assertTrue(true);
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unexpected Exception occurred " + e.getMessage());
        }
        // try retry with a larger buffer 
        try {
            byte[] largerCipherTextBuffer = new byte[plainText128.length * 2 + 16];
            cpl.doFinal(plainText128, 0, plainText128.length, largerCipherTextBuffer);
            assertTrue(true);
        } catch (Exception ex) {
            fail("Retying with larger buffer should have worked  with a larger buffer");
        }

    }

    @Test
    public void testWithUpdatesDecryptAfterShortBufferRetry() throws Exception {
        byte[] cipherText = null;
        Cipher cpl = null;
        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        try {
            cpl = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            GCMParameterSpec gcmParamSpec = new GCMParameterSpec(128, iv); //128 bit auth tag length

            // Encrypt the plain text
            cpl.init(Cipher.ENCRYPT_MODE, key, gcmParamSpec);
            cipherText = cpl.doFinal(plainText128, 0, plainText128.length);

            AlgorithmParameters params = cpl.getParameters();

            cpl = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            cpl.init(Cipher.DECRYPT_MODE, key, params);
            byte[] sbPlainText = new byte[15];
            System.out.println("cipherText.length=" + cipherText.length);
            System.out.println("sbPlainText.length=" + sbPlainText.length);
            cpl.update(cipherText, 0, 5, sbPlainText, 0);
            cpl.doFinal(cipherText, 5, cipherText.length - 5, sbPlainText, 5);
            fail("Failed to get ShortedBufferException");
        } catch (ShortBufferException ex) {
            assertTrue(true);
        }
        // try retry with a larger buffer
        try {
            byte[] lbPlainTextBuffer = new byte[plainText128.length];
            cpl.doFinal(cipherText, 5, cipherText.length - 5, lbPlainTextBuffer, 0);
            assertTrue(Arrays.equals(plainText128, lbPlainTextBuffer));
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("Retying with larger buffer should have worked  with a larger buffer");
        }

    }

    // Respecify parameters twice and it should fail.
    @Test
    public void testWithUpdatesCipherStates() throws Exception {
        Cipher cpl = null;

        try {
            cpl = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            GCMParameterSpec gcmParamSpec = new GCMParameterSpec(128, ivBytes); //128 bit auth tag length
            // Encrypt the plain text

            cpl.init(Cipher.ENCRYPT_MODE, key, gcmParamSpec);
            cpl.doFinal(plainText128, 0, plainText128.length);

            try {
                cpl.init(Cipher.ENCRYPT_MODE, key, gcmParamSpec);
                cpl.update(plainText128, 0, plainText128.length);
                cpl.doFinal(plainText128, 0, plainText128.length);
            } catch (InvalidAlgorithmParameterException e) {
                assertTrue(true);
            }
            try {
                //expected it to fail 
                cpl.update(plainText128, 0, plainText128.length);
                cpl.doFinal(plainText128, 0, plainText128.length);
                fail("Did not get the expected failure");
            } catch (Exception ex) {
                System.err.println(
                        "got expected exception " + ex.getClass() + ": " + ex.getMessage());
            }

            // Try
            cpl.init(Cipher.ENCRYPT_MODE, key);
            cpl.updateAAD(aadBytes, 0, aadBytes.length);

            byte[] result1 = encrypt(cpl);
            byte[] result2 = encrypt(cpl);

            // Expect results to be different as IV is changed after doFinal(),
            // if one is not provided during init().
            assert (!Arrays.equals(result1, result2));

        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException
                | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
                | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            fail("Unexpected exception seen=" + e.getMessage());
        }

    }

    @Test
    public void testCallUpdateFailsSameKeyIV() throws Exception {
        int len = 0;
        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(128, ivBytes); // 128 bit auth tag length
        Cipher ci = createCipher(Cipher.ENCRYPT_MODE, key, gcmParamSpec);
        ci.updateAAD(aadBytes);

        int offset = (plainText128.length > 32) ? 32 : 0;
        byte[] part31_a = new byte[ci.getOutputSize(plainText128.length)];
        byte[] part31_b = new byte[ci.getOutputSize(plainText128.length)];

        // System.out.println( "=====testCaseShortBuffer plainText.length " +
        // plainText.length + " parts31.length " + part31.length);

        len = ci.update(plainText128, 0, plainText128.length - offset, part31_a, 0);

        byte[] part32_a = ci.doFinal(plainText128, plainText128.length - offset, offset);
        byte[] outputText_a = new byte[len + part32_a.length];
        System.arraycopy(part31_a, 0, outputText_a, 0, len);
        System.arraycopy(part32_a, 0, outputText_a, len, part32_a.length);
        try {
            ci.update(plainText128, 0, plainText128.length - offset, part31_b, 0);
            fail("Should have thrown an IllegalStateException");
        } catch (IllegalStateException ex) {
            assert (true);
        } catch (Exception e) {
            fail("Unexpected exception " + e.getClass() + ": [" + e.getMessage() + "] was thrown");

        }


    }

    @Test
    public void testMultipleUpdateWithoutAllocatingExternalBuffer19() throws Exception {

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", getProviderName());
        keyGenerator.init(16 * 8);

        // Generate Key
        SecretKey key = keyGenerator.generateKey();
        byte[] IV = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);

        //When i =0; the buffer sizes are same as failure reported in Jira-48. 
        //Other iterations are to test additional buffer sizes.
        for (int i = 0; i < 18899; i++) {

            byte[] firstUpdate = new byte[i + 10];
            byte[] secondUpdate = new byte[i + 532];
            byte[] thirdUpdate = new byte[i + 8];
            byte[] finalPlainText = new byte[0];
            byte[] allPlainText = new byte[3 * i + 550];

            byte[] cipherText = doMultipleUpdateWithoutAllocatingExternalBufferEncrypt(key, IV,
                    firstUpdate, secondUpdate, thirdUpdate, finalPlainText);

            byte[] decryptedPlainText = doMultipleUpdateWithoutAllocatingExternalBufferDecrypt(
                    cipherText, key, IV);

            assertTrue(Arrays.equals(decryptedPlainText, allPlainText));
        }
    }

    public byte[] doMultipleUpdateWithoutAllocatingExternalBufferEncrypt(SecretKey key, byte[] IV,
            byte[] firstUpdateBytes, byte[] secondUpdateBytes, byte[] thirdUpdateBytes,
            byte[] finalPlainBytes) throws Exception {
        // Get Cipher Instance
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

            // Create SecretKeySpec
            SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

            // Create GCMParameterSpec
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);

            // Initialize Cipher for ENCRYPT_MODE
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
            byte[] encryptedFirstUpdateBytes = cipher.update(firstUpdateBytes, 0,
                    firstUpdateBytes.length);
            byte[] encryptedSecondUpdateBytes = cipher.update(secondUpdateBytes, 0,
                    secondUpdateBytes.length);
            byte[] encryptedThirdUpdateBytes = cipher.update(thirdUpdateBytes, 0,
                    thirdUpdateBytes.length);

            // Perform Encryption
            byte[] finalCipherTextBytes = cipher.doFinal(finalPlainBytes, 0, 0);
            byte[] encryptedAllBytes = new byte[encryptedFirstUpdateBytes.length
                    + encryptedSecondUpdateBytes.length + encryptedThirdUpdateBytes.length
                    + finalCipherTextBytes.length];
            int offset = 0;
            System.arraycopy(encryptedFirstUpdateBytes, 0, encryptedAllBytes, offset,
                    encryptedFirstUpdateBytes.length);
            offset += encryptedFirstUpdateBytes.length;

            System.arraycopy(encryptedSecondUpdateBytes, 0, encryptedAllBytes, offset,
                    encryptedSecondUpdateBytes.length);
            offset += encryptedSecondUpdateBytes.length;
            System.arraycopy(encryptedThirdUpdateBytes, 0, encryptedAllBytes, offset,
                    encryptedThirdUpdateBytes.length);
            offset += encryptedThirdUpdateBytes.length;
            System.arraycopy(finalCipherTextBytes, 0, encryptedAllBytes, offset,
                    finalCipherTextBytes.length);

            return encryptedAllBytes;

        } catch (Exception ex) {

            ex.printStackTrace();
            throw ex;
        }
    }

    public byte[] doMultipleUpdateWithoutAllocatingExternalBufferDecrypt(byte[] cipherText,
            SecretKey key, byte[] IV) throws Exception {
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);

        // Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);

        // Perform Decryption
        byte[] decryptedText = cipher.doFinal(cipherText);

        return decryptedText;
    }

    @Test
    public void testNoDataUpdate20() throws Exception {
        for (int keysizeloop = 1; keysizeloop < 3; keysizeloop++) {

            SecretKey key = new SecretKeySpec(new byte[16 * keysizeloop], "AES"); // key is 16 zero bytes

            for (int i = 0; i < 18899; i++) {
                byte[] plainTextArray = new byte[i];
                byte[] decryptedPlainTextArray = doDecryptNoDataUpdate(
                        doEncryptNoDataUpdate(plainTextArray, key), key);
                assertTrue(Arrays.equals(plainTextArray, decryptedPlainTextArray));

            }

        }
    }

    private byte[] doEncryptNoDataUpdate(byte[] plainTextBytes, SecretKey skey) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, skey, ivSpec);
        cipher.updateAAD("12345678".getBytes());

        byte[] ciphertext = cipher.doFinal(plainTextBytes);
        byte[] encrypted = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encrypted, 0, iv.length);
        System.arraycopy(ciphertext, 0, encrypted, iv.length, ciphertext.length);
        return encrypted;
    }

    private byte[] doDecryptNoDataUpdate(byte[] encrypted, SecretKey skey) throws Exception {

        byte[] iv = Arrays.copyOfRange(encrypted, 0, GCM_IV_LENGTH);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
        cipher.init(Cipher.DECRYPT_MODE, skey, ivSpec);
        cipher.updateAAD("12345678".getBytes());

        byte[] plaintext = cipher.doFinal(encrypted, GCM_IV_LENGTH,
                encrypted.length - GCM_IV_LENGTH);

        return plaintext;
    }

    private byte[] encrypt(Cipher cpl)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] part71 = new byte[cpl.getOutputSize(plainText128.length)];
        // System.out.println ("=======part71 length=" + part71.length);
        int offset = plainText128.length > ARRAY_OFFSET ? ARRAY_OFFSET : 0;
        int len = cpl.update(plainText128, 0, plainText128.length - offset, part71, 0);
        byte[] part72 = cpl.doFinal(plainText128, plainText128.length - offset, offset);
        byte[] outputText7 = new byte[len + part72.length];
        System.arraycopy(part71, 0, outputText7, 0, len);
        System.arraycopy(part72, 0, outputText7, len, part72.length);
        return outputText7;
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
