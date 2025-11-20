/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import ibm.security.internal.spec.CCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

// This test case exercises the AES/CCM cipher using a CCMParameters object

public class BaseTestAESCCM2 extends BaseTestJunit5 {

    public int iterationLimit = 100;
    public int iterationCounter = 0;

    // The plainText string to be encrypted and decrypted will be selected randomly for each iteration.
    public String plainText = null;

    public String plainTextShort = "A short text string to be encrypted.";
    public String plainTextMedium = "A medium text string to be encrypted. A medium text string to be encrypted. A medium text string to be encrypted. A medium text string to be encrypted. A medium text string to be encrypted.";
    public String plainTextLong = "A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted.";

    public int AESKeySize = 0;
    public int AESKeySize128 = 128;
    public int AESKeySize192 = 192;
    public int AESKeySize256 = 256;

    // This CCM TAG LENGTH is specified in bits.  Valid values are:  32, 48, 64, 60, 96, 112, and 128
    // Although initialized here, the ccmTagLength will actually be selected randomly for each iteration.
    public int ccmTagLength = 128;

    // The size of the aad buffer will be selected randomly for each iteration.
    // The contents of the aad buffer will be random data for each iteration.
    public byte[] aad = null;

    private Object myMutexObject = new Object();

    public boolean printJunitTrace = Boolean.valueOf(System.getProperty("com.ibm.jceplus.junit.printJunitTrace"));

    @Test
    public void testAESCCM() throws Exception {
        while (iterationCounter < iterationLimit) {

            iterationCounter++;

            synchronized (myMutexObject) {
                if (printJunitTrace)
                    System.out.println(
                            "\n============================================================");
                if (printJunitTrace)
                    System.out.println("BaseTestAESCCM2.java:  testAESCCM():  BEGIN TEST #"
                            + iterationCounter);
                if (printJunitTrace)
                    System.out.println(
                            "============================================================\n");
            }

            // Select which plainText string to encrypt/decrypt.
            Random randomForPlainText = new Random();
            int whichPlainTextString = randomForPlainText.nextInt(3); // The specified value is excluded
            if (whichPlainTextString == 0) {
                plainText = plainTextShort;
            } else if (whichPlainTextString == 1) {
                plainText = plainTextMedium;
            } else if (whichPlainTextString == 2) {
                plainText = plainTextLong;
            }

            // IF USED, THIS DEBUG BLOCK OF CODE WILL ENSURE THAT THE SAME plaintext WILL BE USED FOR EVERY ITERATION
            // plainText = plainTextShort;


            if (printJunitTrace)
                System.out.println(
                        "BaseTestAESCCM2.java:  testAESCCM():  Original Text : " + plainText);

            // Select which AES key size to use.
            Random randomForKeySize = new Random();
            int whichAESKeySize = randomForKeySize.nextInt(3); // The specified value is excluded
            if (whichAESKeySize == 0) {
                AESKeySize = AESKeySize128;
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestAESCCM2.java:  testAESCCM():  The AES key size is 128.");
            } else if (whichAESKeySize == 1) {
                AESKeySize = AESKeySize192;
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestAESCCM2.java:  testAESCCM():  The AES key size is 192.");
            } else if (whichAESKeySize == 2) {
                AESKeySize = AESKeySize256;
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestAESCCM2.java:  testAESCCM():  The AES key size is 256.");
            }


            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", getProviderName());
            if (printJunitTrace)
                System.out.println("BaseTestAESCCM2.java:  testAESCCM():  The KeyGenerator is a:  "
                        + keyGenerator.getClass().getName());
            keyGenerator.init(AESKeySize);


            // Generate Key
            SecretKey key = keyGenerator.generateKey();


            // IF USED, THIS DEBUG BLOCK OF CODE WILL ENSURE THAT THE SAME AES KEY WILL BE USED FOR EVERY ITERATION
            // byte[] encodedAESKey = { (byte)0xE9, (byte)0x48, (byte)0x68, (byte)0x67, (byte)0x80, (byte)0x6E, (byte)0x89, (byte)0x73, (byte)0xF5, (byte)0xFF, (byte)0x72, (byte)0x18, (byte)0x8A, (byte)0x4E, (byte)0x17, (byte)0x42, (byte)0x71, (byte)0x53, (byte)0xF2, (byte)0x1D, (byte)0x9E, (byte)0x6B, (byte)0x83, (byte)0x1C, (byte)0x46, (byte)0x5C, (byte)0xEC, (byte)0xAF, (byte)0x03, (byte)0x54, (byte)0x40, (byte)0x43  };
            // SecretKeySpec aesKeySpec = new SecretKeySpec( encodedAESKey, "AES");
            // SecretKeyFactory aesKeyFactory = SecretKeyFactory.getInstance( "AES" );
            // key = aesKeyFactory.generateSecret( aesKeySpec );


            // Generate a random IV
            byte[] IV = new byte[computeIVBufferLength()];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(IV);


            // IF USED, THIS DEBUG BLOCK OF CODE WILL ENSURE THAT THE SAME IV WILL BE USED FOR EVERY ITERATION
            // byte[] debugIV = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08  };
            // IV = debugIV;
            if (printJunitTrace)
                System.out
                        .println("BaseTestAESCCM2.java:  testAESCCM():  The IV buffer length is:  "
                                + IV.length);
            if (printJunitTrace)
                System.out.println(
                        "BaseTestAESCCM2.java:  testAESCCM():  The random IV buffer contents are:");
            if (printJunitTrace)
                System.out.println(toHexString(IV));


            // Generate a random AAD (limit the aad byte length to the range 1 thru 2048)
            Random randomForAAD = new Random();
            int aadByteLength = randomForAAD.nextInt(2048) + 1; // Any value in the range 1 thru 2048
            aad = new byte[aadByteLength];
            secureRandom.nextBytes(aad);


            // IF USED, THIS DEBUG BLOCK OF CODE WILL ENSURE THAT THE SAME IV WILL BE USED FOR EVERY ITERATION
            // byte[] debugAAD = { (byte)0x09, (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15, (byte)0x16 };
            // aad=debugAAD;


            if (printJunitTrace)
                System.out.println("BaseTestAESCCM2.java:  testAESCCM():  There are "
                        + aadByteLength + " random 'aad' bytes for this iteration.");
            if (printJunitTrace)
                System.out.println(
                        "BaseTestAESCCM2.java:  testAESCCM():  The random 'aad' bytes for this iteration are:");
            if (printJunitTrace)
                System.out.println(toHexString(aad) + "\n");


            // Generate a random tag length (one of:  128, 112, 96, 80, 64 )
            int ccmTagLength = computeTagLength();


            // IF USED, THIS DEBUG BLOCK OF CODE WILL ENSURE THAT THE CCM TAG LENGTH WILL BE USED FOR EVERY ITERATION
            // ccmTagLength = 64;  // DEBUG
            if (printJunitTrace)
                System.out.println(
                        "BaseTestAESCCM2.java:  testAESCCM():  The random 'tag length' is:  "
                                + ccmTagLength);


            // DO ENCRYPTION
            byte[] cipherText = encrypt(plainText.getBytes(), key, IV, ccmTagLength);

            if (printJunitTrace)
                System.out
                        .println("BaseTestAESCCM2.java:  testAESCCM():  Encrypted Text (Final) : ");
            if (cipherText != null) {
                if (cipherText.length == 0) {
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  testAESCCM():  ERROR:  The encrypted text byte array is NOT NULL, but it has LENGTH = 0.    Iteration counter = "
                                        + iterationCounter);
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                } else {
                    if (printJunitTrace)
                        System.out.println(toHexString(cipherText));
                }
            } else { // else cipherText == null
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestAESCCM2.java:  testAESCCM():  ERROR:  The encrypted text is NULL.    Iteration counter = "
                                    + iterationCounter);
                RuntimeException rtex = new RuntimeException();
                rtex.printStackTrace(System.out);
                Assertions.fail();
            }



            // DO DECRYPTION
            String decryptedText = decrypt(cipherText, key, IV, ccmTagLength);


            if (decryptedText != null) {
                if (printJunitTrace)
                    System.out.println("Decrypted Text (Final) : " + decryptedText);
            }

            // Compare the plainText to the decryptedText
            if (decryptedText.equals(plainText) == false) {
                if (printJunitTrace)
                    System.out.println(
                            "\nBaseTestAESCCM2.java:  testAESCCM():  ERROR:  The decryptedText does NOT MATCH the plainText.    Iteration counter = "
                                    + iterationCounter);
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestAESCCM2.java:  testAESCCM():   plainText String     =  "
                                    + plainText);
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestAESCCM2.java:  testAESCCM():   decryptedText String =  "
                                    + decryptedText);

                if (printJunitTrace)
                    System.out.println(
                            "\nBaseTestAESCCM2.java:  testAESCCM():   The plainText bytes are: ");
                if (printJunitTrace)
                    System.out.println(toHexString(plainText.getBytes()));
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestAESCCM2.java:  testAESCCM():   The decryptedText bytes are: ");
                if (printJunitTrace)
                    System.out.println(toHexString(decryptedText.getBytes()));
                Assertions.fail();
            } else {
                plainText = null;
                decryptedText = null;
            }


            synchronized (myMutexObject) {
                if (printJunitTrace)
                    System.out.println(
                            "\n==========================================================");
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestAESCCM2.java:  testAESCCM():  END TEST #" + iterationCounter);
                if (printJunitTrace)
                    System.out.println(
                            "==========================================================\n");
            }


        } // end iteration loop


        synchronized (myMutexObject) {
            if (printJunitTrace)
                System.out.println(
                        "\n===================================================================================================");
            if (printJunitTrace)
                System.out.println(
                        "BaseTestAESCCM2.java:  testAESCCM():  END OF SUCCESSFUL TESTS.  The iteration counter = "
                                + iterationCounter);
            if (printJunitTrace)
                System.out.println(
                        "BaseTestAESCCM2.java:  testAESCCM():  END OF SUCCESSFUL TESTS.  The iteration limit   = "
                                + iterationLimit);
            if (printJunitTrace)
                System.out.println(
                        "===================================================================================================\n");
        }


    } // end testAESCCM()



    private byte[] encrypt(byte[] plaintext, SecretKey key, byte[] IV, int ccmTagLength)
            throws Exception {
        synchronized (myMutexObject) {
            if (printJunitTrace)
                System.out.println(
                        "\n=========================================================================");
            if (printJunitTrace)
                System.out.println(
                        "BaseTestAESCCM2.java:  encrypt():  *****   BEGIN ENCRYPTION METHOD  *****");
            if (printJunitTrace)
                System.out.println(
                        "=========================================================================\n");
        }

        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", getProviderName());
        if (printJunitTrace)
            System.out.println(
                    "BaseTestAESCCM2.java:  encrypt():  The encryption cipher is a:                "
                            + cipher.getClass().getName());
        if (printJunitTrace)
            System.out.println(
                    "BaseTestAESCCM2.java:  encrypt():  The provider of the encryption cipher is:  "
                            + cipher.getProvider());

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

        // Create CCMParameterSpec
        if (printJunitTrace)
            System.out.println(
                    "BaseTestAESCCM2.java:  encrypt():  The encryption tag length (in bits)  is:  "
                            + ccmTagLength);
        if (printJunitTrace)
            System.out.println(
                    "BaseTestAESCCM2.java:  encrypt():  The encryption IV length (in bytes) is:  "
                            + IV.length);
        CCMParameterSpec ccmParameterSpec = new CCMParameterSpec(ccmTagLength, IV); // ccmTagLength is specified in bits

        // Create a CCMParameters object
        AlgorithmParameters ccmParameters = null;
        try {
            ccmParameters = AlgorithmParameters.getInstance("CCM", getProviderName());
            ccmParameters.init(ccmParameterSpec);
        } catch (Exception ex) {
            if (printJunitTrace)
                System.out.println(
                        "BaseTestAESCCM2ForAESCCMParameters.java:  encrypt():  ERROR:  The unexpected exception below was thrown while creating a CCMParameters object.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ccmParameters);

        // Initialize encryption Cipher with AAD
        cipher.updateAAD(aad);


        if (printJunitTrace)
            System.out.println(
                    "BaseTestAESCCM2.java:  encrypt():  MAKING OCK ENCRYPTION CALL FROM encrypt() METHOD !!!");


        // Perform Encryption
        byte[] cipherText = null;
        try {
            Random randomForMethodChoice = new Random();
            int whichMethod = randomForMethodChoice.nextInt(5); // The specified value is excluded


            if (whichMethod == 0) {
                if (printJunitTrace)
                    System.out.println("BaseTestAESCCM2.java:  encrypt():  METHOD CHOSEN = 0");

                // Try to encrypt the plaintext with cipher.update()
                try {
                    cipher.update(plaintext);
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  encrypt():  ERROR:  An exception should have been thrown.  ");
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                } catch (ProviderException proex) {
                    // do nothing.  This exception is expected because AES/CCM does not support cipher.update().
                }

                byte[] cipherText2 = cipher.doFinal(plaintext);

                // All the encryption was performed on Cipher.doFinal( )
                cipherText = new byte[cipherText2.length];
                System.arraycopy(cipherText2, 0, cipherText, 0, cipherText2.length);
            } else if (whichMethod == 1) {
                if (printJunitTrace)
                    System.out.println("BaseTestAESCCM2.java:  encrypt():  METHOD CHOSEN = 1");

                try {
                    cipher.update(plaintext, 0, plaintext.length);
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  encrypt():  ERROR:  An exception should have been thrown.  ");
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                } catch (ProviderException proex) {
                    // do nothing.  This exception is expected because AES/CCM does not support cipher.update().
                }

                byte[] cipherText2 = cipher.doFinal(plaintext, 0, plaintext.length);

                // All the encryption was performed on Cipher.doFinal( )
                cipherText = new byte[cipherText2.length];
                System.arraycopy(cipherText2, 0, cipherText, 0, cipherText2.length);
            } else if (whichMethod == 2) {
                if (printJunitTrace)
                    System.out.println("BaseTestAESCCM2.java:  encrypt():  METHOD CHOSEN = 2");
                int outputSizeNeeded = cipher.getOutputSize(plaintext.length);
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestAESCCM2.java:  encrypt():  The outputSizeNeeded is:                    "
                                    + outputSizeNeeded);
                byte[] cipherText1 = new byte[outputSizeNeeded];

                try {
                    cipher.update(plaintext, 0, plaintext.length,
                            cipherText1);
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  encrypt():  ERROR:  An exception should have been thrown.  ");
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                } catch (ProviderException proex) {
                    // do nothing.  This exception is expected because AES/CCM does not support cipher.update().
                }

                int outputLengthNeeded = cipher.getOutputSize(plaintext.length);
                byte[] cipherText2 = new byte[outputLengthNeeded];
                int cipherText2Length = cipher.doFinal(plaintext, 0, plaintext.length, cipherText2);

                if (cipherText2Length != cipherText2.length) {
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  encrypt():  ERROR:  cipherText2Length is not equal to cipherText2.length.  ");
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                }

                // All the encryption was performed on Cipher.doFinal( )
                cipherText = new byte[cipherText2.length];
                System.arraycopy(cipherText2, 0, cipherText, 0, cipherText2.length);
            } else if (whichMethod == 3) {
                if (printJunitTrace)
                    System.out.println("BaseTestAESCCM2.java:  encrypt():  METHOD CHOSEN = 3");
                int outputSizeNeeded = cipher.getOutputSize(plaintext.length);
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestAESCCM2.java:  encrypt():  The outputSizeNeeded is:                    "
                                    + outputSizeNeeded);
                byte[] cipherText1 = new byte[outputSizeNeeded];

                try {
                    cipher.update(plaintext, 0, plaintext.length,
                            cipherText1, 0);
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  encrypt():  ERROR.  An exception should have been thrown.  ");
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                } catch (ProviderException proex) {
                    // do nothing.  This exception is expected because AES/CCM does not support cipher.update().
                }

                int outputLengthNeeded = cipher.getOutputSize(plaintext.length);
                byte[] cipherText2 = new byte[outputLengthNeeded];
                int cipherText2Length = cipher.doFinal(plaintext, 0, plaintext.length, cipherText2,
                        0);

                if (cipherText2Length != cipherText2.length) {
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  encrypt():  ERROR:  cipherText2Length is not equal to cipherText2.length.  ");
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                }

                // All the encryption was performed on Cipher.doFinal( )
                cipherText = new byte[cipherText2.length];
                System.arraycopy(cipherText2, 0, cipherText, 0, cipherText2.length);
            } else if (whichMethod == 4) {
                if (printJunitTrace)
                    System.out.println("BaseTestAESCCM2.java:  encrypt():  METHOD CHOSEN = 4");

                ByteBuffer byteBuffer1 = ByteBuffer.allocate(plaintext.length);
                byteBuffer1.put(plaintext);
                int outputSizeNeeded = cipher.getOutputSize(plaintext.length);
                ByteBuffer byteBuffer2 = ByteBuffer.allocate(outputSizeNeeded);
                try {
                    cipher.update(byteBuffer1, byteBuffer2);
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  encrypt():  ERROR.  An exception should have been thrown.  ");
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                } catch (ProviderException proex) {
                    // do nothing.  This exception is expected because AES/CCM does not support cipher.update().
                }

                byteBuffer1 = ByteBuffer.allocate(plaintext.length);
                byteBuffer1.put(plaintext);
                outputSizeNeeded = cipher.getOutputSize(plaintext.length);
                byteBuffer2 = ByteBuffer.allocate(outputSizeNeeded);
                int cipherText2Length = cipher.doFinal(byteBuffer1, byteBuffer2);
                byte[] cipherText2 = byteBuffer2.array();

                if (cipherText2Length != cipherText2.length) {
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  encrypt():  ERROR:  cipherText2Length is not equal to cipherText2.length.  ");
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                }

                // All the encryption was performed on Cipher.doFinal( )
                cipherText = new byte[cipherText2.length];
                System.arraycopy(cipherText2, 0, cipherText, 0, cipherText2.length);
            }

        } catch (Exception ex) {
            if (printJunitTrace)
                System.out.println(
                        "BaseTestAESCCM2.java:  encrypt():  ERROR:  The following exception was thrown.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        if (printJunitTrace)
            System.out.println("BaseTestAESCCM2.java:  encrypt():  The encrypted bytes are:");
        if (printJunitTrace)
            System.out.println(toHexString(cipherText) + "\n");


        synchronized (myMutexObject) {
            if (printJunitTrace)
                System.out.println(
                        "\n=========================================================================");
            if (printJunitTrace)
                System.out.println(
                        "BaseTestAESCCM2.java:  encrypt():  *****   END ENCRYPTION METHOD    *****");
            if (printJunitTrace)
                System.out.println(
                        "=========================================================================\n");
        }

        return cipherText;
    } // end encrypt( )



    private String decrypt(byte[] cipherText, SecretKey key, byte[] IV, int ccmTagLength)
            throws Exception {

        synchronized (myMutexObject) {
            if (printJunitTrace)
                System.out.println(
                        "\n=========================================================================");
            if (printJunitTrace)
                System.out.println(
                        "BaseTestAESCCM2.java:  decrypt():  *****   BEGIN DECRYPTION METHOD  *****");
            if (printJunitTrace)
                System.out.println(
                        "=========================================================================\n");
        }

        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", getProviderName());
        if (printJunitTrace)
            System.out.println(
                    "BaseTestAESCCM2.java:  decrypt():  The decryption cipher is a:                "
                            + cipher.getClass().getName());
        if (printJunitTrace)
            System.out.println(
                    "BaseTestAESCCM2.java:  decrypt():  The provider of the decryption cipher is:  "
                            + cipher.getProvider());

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

        // Create CCMParameterSpec
        if (printJunitTrace)
            System.out.println(
                    "BaseTestAESCCM2.java:  decrypt():  The decryption tag length (in bits)  is:  "
                            + ccmTagLength);
        if (printJunitTrace)
            System.out.println(
                    "BaseTestAESCCM2.java:  decrypt():  The decryption IV length (in bytes) is:  "
                            + IV.length);
        CCMParameterSpec ccmParameterSpec = new CCMParameterSpec(ccmTagLength, IV); // ccmTagLength is specified in bits

        // Create a CCMParameters object
        AlgorithmParameters ccmParameters = null;
        try {
            ccmParameters = AlgorithmParameters.getInstance("CCM", getProviderName());
            ccmParameters.init(ccmParameterSpec);
        } catch (Exception ex) {
            if (printJunitTrace)
                System.out.println(
                        "BaseTestAESCCM2ForAESCCMParameters.java:  decrypt():  ERROR:  The unexpected exception below was thrown while creating a CCMParameters object.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        // Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ccmParameters);

        // Initialize decryption Cipher with AAD
        cipher.updateAAD(aad);


        if (printJunitTrace)
            System.out.println(
                    "BaseTestAESCCM2.java:  decrypt():  MAKING OCK DECRYPTION CALL FROM decrypt() METHOD !!!");


        // Perform Decryption
        byte[] decryptedText = null;
        try {
            Random randomForMethodChoice = new Random();
            int whichMethod = randomForMethodChoice.nextInt(5); // The specified value is excluded


            if (whichMethod == 0) {
                if (printJunitTrace)
                    System.out.println("BaseTestAESCCM2.java:  decrypt():  METHOD CHOSEN = 0");

                // Decrypt the cipherText
                try {
                    cipher.update(cipherText);
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  decrypt():  ERROR.  Cipher.update( ) should have thrown a RuntimeException.  ");
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                } catch (RuntimeException rtex) {
                    // Do nothing.  Cipher.update() for decryption is not supported.
                }

                byte[] decryptedText2 = cipher.doFinal(cipherText);

                // All the decryption was performed on Cipher.doFinal( )
                decryptedText = new byte[decryptedText2.length];
                System.arraycopy(decryptedText2, 0, decryptedText, 0, decryptedText2.length);
            } else if (whichMethod == 1) {
                if (printJunitTrace)
                    System.out.println("BaseTestAESCCM2.java:  decrypt():  METHOD CHOSEN = 1");

                // Decrypt the cipherText
                try {
                    cipher.update(cipherText, 0, cipherText.length);
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  decrypt():  ERROR.  Cipher.update( ) should have thrown a RuntimeException.  ");
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                } catch (RuntimeException rtex) {
                    // Do nothing.  Cipher.update() for decryption is not supported.
                }

                byte[] decryptedText2 = cipher.doFinal(cipherText, 0, cipherText.length);

                // All the decryption was performed on Cipher.doFinal( )
                decryptedText = new byte[decryptedText2.length];
                System.arraycopy(decryptedText2, 0, decryptedText, 0, decryptedText2.length);

            } else if (whichMethod == 2) {
                if (printJunitTrace)
                    System.out.println("BaseTestAESCCM2.java:  decrypt():  METHOD CHOSEN = 2");
                int outputSizeNeeded = cipher.getOutputSize(cipherText.length);
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestAESCCM2.java:  decrypt():  The outputSizeNeeded is:                    "
                                    + outputSizeNeeded);
                byte[] decryptedText1 = new byte[outputSizeNeeded];
                try {
                    cipher.update(cipherText, 0, cipherText.length,
                            decryptedText1);
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  decrypt():  ERROR.  Cipher.update( ) should have thrown a RuntimeException.  ");
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                } catch (RuntimeException rtex) {
                    // Do nothing.  Cipher.update() for decryption is not supported.
                }

                outputSizeNeeded = cipher.getOutputSize(cipherText.length);
                byte[] decryptedText2 = new byte[outputSizeNeeded];
                int decryptedText2Length = cipher.doFinal(cipherText, 0, cipherText.length,
                        decryptedText2);

                if (decryptedText2Length != decryptedText2.length) {
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  decrypt():  ERROR:  decryptedText2Length is not equal to decryptedText2.length.  ");
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                }

                // All the decryption was performed on Cipher.doFinal( )
                decryptedText = new byte[decryptedText2.length];
                System.arraycopy(decryptedText2, 0, decryptedText, 0, decryptedText2.length);
            } else if (whichMethod == 3) {
                if (printJunitTrace)
                    System.out.println("BaseTestAESCCM2.java:  decrypt():  METHOD CHOSEN = 3");
                int outputSizeNeeded = cipher.getOutputSize(cipherText.length);
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestAESCCM2.java:  decrypt():  The outputSizeNeeded is:                    "
                                    + outputSizeNeeded);
                byte[] decryptedText1 = new byte[outputSizeNeeded];
                try {
                    cipher.update(cipherText, 0, cipherText.length,
                            decryptedText1, 0);
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  decrypt():  ERROR.  Cipher.update( ) should have thrown a RuntimeException.  ");
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                } catch (RuntimeException rtex) {
                    // Do nothing.  Cipher.update() for decryption is not supported.
                }

                outputSizeNeeded = cipher.getOutputSize(cipherText.length);
                byte[] decryptedText2 = new byte[outputSizeNeeded];
                int decryptedText2Length = cipher.doFinal(cipherText, 0, cipherText.length,
                        decryptedText2, 0);

                if (decryptedText2Length != decryptedText2.length) {
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  decrypt():  ERROR:  decryptedText2Length is not equal to decryptedText2.length.  ");
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                }

                // All the decryption was performed on Cipher.doFinal( )
                decryptedText = new byte[decryptedText2.length];
                System.arraycopy(decryptedText2, 0, decryptedText, 0, decryptedText2.length);
            } else if (whichMethod == 4) {
                if (printJunitTrace)
                    System.out.println("BaseTestAESCCM2.java:  decrypt():  METHOD CHOSEN = 4");
                int outputSizeNeeded = cipher.getOutputSize(cipherText.length);
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestAESCCM2.java:  decrypt():  The outputSizeNeeded is:                    "
                                    + outputSizeNeeded);

                ByteBuffer byteBuffer1 = ByteBuffer.allocate(cipherText.length);
                byteBuffer1.put(cipherText);

                ByteBuffer byteBuffer2 = ByteBuffer.allocate(outputSizeNeeded);

                try {
                    cipher.update(byteBuffer1, byteBuffer2);
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  decrypt():  ERROR.  Cipher.update( ) should have thrown a RuntimeException.  ");
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                } catch (RuntimeException rtex) {
                    // Do nothing.  Cipher.update() for decryption is not supported.
                }

                int decryptedText2Length = cipher.doFinal(byteBuffer1, byteBuffer2);
                byte[] decryptedText2 = byteBuffer2.array();

                if (decryptedText2Length != decryptedText2.length) {
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestAESCCM2.java:  decrypt():  ERROR:  decryptedText2Length is not equal to decryptedText2.length.  ");
                    RuntimeException rtex = new RuntimeException();
                    rtex.printStackTrace(System.out);
                    Assertions.fail();
                }

                // All the decryption was performed on Cipher.doFinal( )
                decryptedText = new byte[decryptedText2.length];
                System.arraycopy(decryptedText2, 0, decryptedText, 0, decryptedText2.length);
            }

        } catch (AEADBadTagException abte) {
            if (printJunitTrace)
                System.out.println(
                        "BaseTestAESCCM2.java:  decrypt():  ERROR:  The following AEADBadTagException was thrown on the cipher.doFinal() call.");
            abte.printStackTrace(System.out);
            Assertions.fail();
        } catch (Exception ex) {
            if (printJunitTrace)
                System.out.println(
                        "BaseTestAESCCM2.java:  decrypt():  ERROR:  The following exception was thrown.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        synchronized (myMutexObject) {
            if (printJunitTrace)
                System.out.println(
                        "\n=========================================================================");
            if (printJunitTrace)
                System.out.println(
                        "BaseTestAESCCM2.java:  decrypt():  *****    END DECRYPTION METHOD   *****");
            if (printJunitTrace)
                System.out.println(
                        "=========================================================================\n");
        }

        return new String(decryptedText);
    } // end decrypt( )



    // This CCM tag length is specified in bits.  Valid values are:  32, 48, 64, 80, 96, 112, 128
    // The ccmTagLength will be selected randomly for each iteration.
    private static int computeTagLength() {
        int ccmTagLength = 0;

        // Generate a random tag length of:  32, 48, 64, 80, 96, 112, or 128)
        Random randomForTagLength = new Random();
        int whichTagLength = randomForTagLength.nextInt(7); // The specified value is excluded
        if (whichTagLength == 0) {
            ccmTagLength = 128;
        } else if (whichTagLength == 1) {
            ccmTagLength = 112;
        } else if (whichTagLength == 2) {
            ccmTagLength = 96;
        } else if (whichTagLength == 3) {
            ccmTagLength = 80;
        } else if (whichTagLength == 4) {
            ccmTagLength = 64;
        } else if (whichTagLength == 5) {
            ccmTagLength = 48;
        } else if (whichTagLength == 6) {
            ccmTagLength = 32;
        }
        return ccmTagLength;
    }


    // The IV buffer length is specified in bytes.  Valid values are 7 thru 13 inclusive.
    // The ivBufferLength will be selected randomly for each iteration.
    private static int computeIVBufferLength() {
        int ivBufferLength = 0;

        // Generate a random IV buffer length ( 7 bytes thru 13 bytes inclusive )
        Random randomForIVBufferLength = new Random();
        int whichIVBufferLength = randomForIVBufferLength.nextInt(7); // The specified value is excluded
        if (whichIVBufferLength == 0) {
            ivBufferLength = 13;
        } else if (whichIVBufferLength == 1) {
            ivBufferLength = 12;
        } else if (whichIVBufferLength == 2) {
            ivBufferLength = 11;
        } else if (whichIVBufferLength == 3) {
            ivBufferLength = 10;
        } else if (whichIVBufferLength == 4) {
            ivBufferLength = 9;
        } else if (whichIVBufferLength == 5) {
            ivBufferLength = 8;
        } else if (whichIVBufferLength == 6) {
            ivBufferLength = 7;
        }
        return ivBufferLength;
    }

    /** * Converts a byte array to hex string */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
                'E', 'F'};
        int len = block.length;
        int high = 0;
        int low = 0;

        for (int i = 0; i < len; i++) {
            if (i % 16 == 0)
                buf.append('\n');
            high = ((block[i] & 0xf0) >> 4);
            low = (block[i] & 0x0f);
            buf.append(hexChars[high]);
            buf.append(hexChars[low]);
            buf.append(' ');
        }
        buf.append('\n');

        return buf.toString();
    }

}
