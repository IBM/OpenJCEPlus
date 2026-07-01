/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * This test case exercises the AES/CCM cipher using a CCMParameterSpec object.
 */
public class BaseTestAESCCMInteropBC extends BaseTestJunit5Interop {

    public static int iterationLimit = 100;
    public static int iterationCounter = 0;

    // The plainText string to be encrypted and decrypted will be selected randomly for each iteration.
    public static String plainText = null;

    public static String plainTextShort = "A short text string to be encrypted.";
    public static String plainTextMedium = "A medium text string to be encrypted. A medium text string to be encrypted. A medium text string to be encrypted. A medium text string to be encrypted. A medium text string to be encrypted.";
    public static String plainTextLong = "A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted. A long text string to be encrypted.";

    public static int AESKeySize = 0;
    public static int AESKeySize128 = 128;
    public static int AESKeySize192 = 192;
    public static int AESKeySize256 = 256;

    // This CCM TAG LENGTH is specified in bits.  Valid values are:  32, 48, 64, 80, 96, 112, 128
    // Although initialized here, the ccmTagLength will actually be selected randomly for each iteration.
    public static int ccmTagLength = 128;

    // The size of the aad buffer will be selected randomly for each iteration.
    // The contents of the aad buffer will be random data for each iteration.
    public static byte[] aad = null;

    private static Object myMutexObject = new Object();

    public static String encryptionProvider = null;
    public static String decryptionProvider = null;
    public static boolean printJunitTrace = false;

    @Test
    public void testAESCCM() throws Exception {
        while (iterationCounter < iterationLimit) {

            iterationCounter++;

            synchronized (myMutexObject) {
                if (printJunitTrace)
                    System.out.println(
                            "\n=============================================================");
                if (printJunitTrace)
                    System.out.println("BaseTestInteropBC.java:  testAESCCM():  BEGIN TEST #"
                            + iterationCounter);
                if (printJunitTrace)
                    System.out.println(
                            "=============================================================\n");
            }

            // Select the encryption provider
            Random randomForEncryptionProviderSelection = new Random();
            int whichEncryptionProvider = randomForEncryptionProviderSelection.nextInt(2); // The specified value is excluded
            if (whichEncryptionProvider == 0) {
                encryptionProvider = getProviderName();
                decryptionProvider = getInteropProviderName();
            } else { // else whichEncryptionProvider == 1
                encryptionProvider = getInteropProviderName();
                decryptionProvider = getProviderName();
            }

            if (printJunitTrace) {
                System.out.println(
                        "BaseTestInteropBC.java:  testAESCCM():  The encryption provider is:  "
                                + encryptionProvider);
                System.out.println(
                        "BaseTestInteropBC.java:  testAESCCM():  The decryption provider is:  "
                                + decryptionProvider);
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
                        "BaseTestInteropBC.java:  testAESCCM():  Original Text : " + plainText);

            // Select which AES key size to use.
            Random randomForKeySize = new Random();
            int whichAESKeySize = randomForKeySize.nextInt(3); // The specified value is excluded
            if (whichAESKeySize == 0) {
                AESKeySize = AESKeySize128;
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestInteropBC.java:  testAESCCM():  The AES key size is 128.");
            } else if (whichAESKeySize == 1) {
                AESKeySize = AESKeySize192;
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestInteropBC.java:  testAESCCM():  The AES key size is 192.");
            } else if (whichAESKeySize == 2) {
                AESKeySize = AESKeySize256;
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestInteropBC.java:  testAESCCM():  The AES key size is 256.");
            }

            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", encryptionProvider);
            if (printJunitTrace)
                System.out
                        .println("BaseTestInteropBC.java:  testAESCCM():  The KeyGenerator is a:  "
                                + keyGenerator.getClass().getName());
            keyGenerator.init(AESKeySize);

            // Generate Key
            SecretKey key = keyGenerator.generateKey();
            byte[] aesKeyBytes = key.getEncoded();

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
                System.out.println(
                        "BaseTestInteropBC.java:  testAESCCM():  The random IV bytes are:");
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
                System.out.println("BaseTestInteropBC.java:  testAESCCM():  There are "
                        + aadByteLength + " random 'aad' bytes for this iteration.");
            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  testAESCCM():  The random 'aad' bytes for this iteration are:");
            if (printJunitTrace)
                System.out.println(toHexString(aad) + "\n");

            // Generate a random tag length (one of:  128, 112, 96, 80, 64 )
            int ccmTagLength = computeTagLength();

            // IF USED, THIS DEBUG BLOCK OF CODE WILL ENSURE THAT THE CCM TAG LENGTH WILL BE USED FOR EVERY ITERATION
            // ccmTagLength = 64;  // DEBUG
            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  testAESCCM():  The random 'tag length' is:  "
                                + ccmTagLength);

            // DO ENCRYPTION
            byte[] cipherText = encrypt(plainText.getBytes(), aesKeyBytes, IV, ccmTagLength);

            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  testAESCCM():  Encrypted Text (Final) : ");
            if (cipherText != null) {
                if (cipherText.length == 0) {
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestInteropBC.java:  testAESCCM():  ERROR:  The encrypted text byte array is NOT NULL, but it has LENGTH = 0.    Iteration counter = "
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
                            "BaseTestInteropBC.java:  testAESCCM():   ERROR:  The encrypted text is NULL.    Iteration counter = "
                                    + iterationCounter);
                RuntimeException rtex = new RuntimeException();
                rtex.printStackTrace(System.out);
                Assertions.fail();
            }

            // DO DECRYPTION
            String decryptedText = decrypt(cipherText, aesKeyBytes, IV, ccmTagLength);

            if (decryptedText != null) {
                if (printJunitTrace)
                    System.out.println("Decrypted Text (Final) : " + decryptedText);
            }

            // Compare the plainText to the decryptedText
            if (decryptedText.equals(plainText) == false) {
                if (printJunitTrace)
                    System.out.println(
                            "\nBaseTestInteropBC.java:  testAESCCM():  ERROR:   The decryptedText does NOT MATCH the plainText.    Iteration counter = "
                                    + iterationCounter);
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestInteropBC.java:  testAESCCM():   plainText String     =  "
                                    + plainText);
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestInteropBC.java:  testAESCCM():   decryptedText String =  "
                                    + decryptedText);

                if (printJunitTrace)
                    System.out.println(
                            "\nBaseTestInteropBC.java:  testAESCCM():   The plainText bytes are: ");
                if (printJunitTrace)
                    System.out.println(toHexString(plainText.getBytes()));
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestInteropBC.java:  testAESCCM():   The decryptedText bytes are: ");
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
                            "\n===========================================================");
                if (printJunitTrace)
                    System.out.println("BaseTestInteropBC.java:  testAESCCM():  END TEST #"
                            + iterationCounter);
                if (printJunitTrace)
                    System.out.println(
                            "===========================================================\n");
            }
        } // end iteration loop

        synchronized (myMutexObject) {
            if (printJunitTrace)
                System.out.println(
                        "\n=======================================================================================================");
            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  testAESCCM():  END OF SUCCESSFUL TESTS.  The iteration counter = "
                                + iterationCounter);
            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  testAESCCM():  END OF SUCCESSFUL TESTS.  The iteration limit   = "
                                + iterationLimit);
            if (printJunitTrace)
                System.out.println(
                        "=======================================================================================================\n");
        }
    } // end testAESCCM()

    /**
     * Tests that engineDoFinal correctly uses inputLen (not input.length) for the output buffer
     * size check during cross-provider interop with BouncyCastle.
     *
     * Exercises two cross-provider scenarios, each with a large input backing array where only a
     * slice is passed via inputOffset + inputLen, and the output buffer is exactly the right size
     * for that slice.
     *
     * Scenario A: OpenJCEPlus encrypts a slice → BC decrypts → plaintext verified.
     * Scenario B: BC encrypts → OpenJCEPlus decrypts a slice → plaintext verified.
     */
    @Test
    public void testAESCCMDoFinalWithInputSliceInterop() throws Exception {
        // Fixed parameters for deterministic, readable test.
        int ccmTagLengthBits = 128;
        int tagLenInBytes    = ccmTagLengthBits / 8; // 16
        byte[] iv = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                     (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                     (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c,
                     (byte) 0x0d};
        byte[] aadBytes = {(byte) 0x09, (byte) 0x10, (byte) 0x11, (byte) 0x12,
                           (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16};

        // Generate a shared 128-bit AES key via OpenJCEPlus.
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", getProviderName());
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();
        byte[] aesKeyBytes = key.getEncoded();
        SecretKeySpec keySpec = new SecretKeySpec(aesKeyBytes, "AES");

        // The actual plaintext payload is 20 bytes, embedded inside a 100-byte backing array
        // at offset 40. This exercises the fix for issue #1564 where engineDoFinal incorrectly
        // used input.length instead of inputLen for the output buffer size check.
        // See: https://github.com/IBM/OpenJCEPlus/issues/1564 for more information on failing scenarios.
        byte[] plaintext = "InteropSliceTest1234".getBytes(); // exactly 20 bytes
        int inputOffset = 40;
        int inputLen    = plaintext.length; // 20
        byte[] inputBacking = new byte[100];
        System.arraycopy(plaintext, 0, inputBacking, inputOffset, inputLen);

        // -----------------------------------------------------------------------
        // Scenario A: OpenJCEPlus encrypts the slice → BC decrypts → verify
        // -----------------------------------------------------------------------
        ibm.security.internal.spec.CCMParameterSpec ccmParamEnc =
                new ibm.security.internal.spec.CCMParameterSpec(ccmTagLengthBits, iv);
        Cipher encCipherOJP = Cipher.getInstance("AES/CCM/NoPadding", getProviderName());
        encCipherOJP.init(Cipher.ENCRYPT_MODE, keySpec, ccmParamEnc);
        encCipherOJP.updateAAD(aadBytes);

        // Output buffer sized exactly for the slice: inputLen + tagLenInBytes = 36 bytes.
        // Before the fix for issue #1564, this would throw a ShortBufferException
        // because the check incorrectly used input.length (100) instead of inputLen (20).
        // See: https://github.com/IBM/OpenJCEPlus/issues/1564 for more information on failing scenarios.
        int encOutputLen = inputLen + tagLenInBytes; // 36
        byte[] ciphertextA = new byte[encOutputLen];
        int bytesEncrypted = encCipherOJP.doFinal(inputBacking, inputOffset, inputLen, ciphertextA, 0);

        Assertions.assertEquals(encOutputLen, bytesEncrypted,
                "Scenario A: OpenJCEPlus encrypted byte count should equal inputLen + tagLenInBytes");

        // BC decrypts the ciphertext produced by OpenJCEPlus.
        org.bouncycastle.crypto.MultiBlockCipher bcEngine =
                org.bouncycastle.crypto.engines.AESEngine.newInstance();
        org.bouncycastle.crypto.params.AEADParameters bcParams =
                new org.bouncycastle.crypto.params.AEADParameters(
                        new org.bouncycastle.crypto.params.KeyParameter(aesKeyBytes),
                        ccmTagLengthBits, iv, null);
        org.bouncycastle.crypto.modes.CCMModeCipher bcDecCipher =
                org.bouncycastle.crypto.modes.CCMBlockCipher.newInstance(bcEngine);
        bcDecCipher.init(false, bcParams);
        bcDecCipher.processAADBytes(aadBytes, 0, aadBytes.length);
        byte[] decryptedA = new byte[bcDecCipher.getOutputSize(ciphertextA.length)];
        int decLen = bcDecCipher.processBytes(ciphertextA, 0, ciphertextA.length, decryptedA, 0);
        bcDecCipher.doFinal(decryptedA, decLen);

        Assertions.assertArrayEquals(plaintext, decryptedA,
                "Scenario A: BC-decrypted bytes must match original plaintext");

        // -----------------------------------------------------------------------
        // Scenario B: BC encrypts → OpenJCEPlus decrypts the slice → verify
        // -----------------------------------------------------------------------
        org.bouncycastle.crypto.MultiBlockCipher bcEngineB =
                org.bouncycastle.crypto.engines.AESEngine.newInstance();
        org.bouncycastle.crypto.params.AEADParameters bcParamsB =
                new org.bouncycastle.crypto.params.AEADParameters(
                        new org.bouncycastle.crypto.params.KeyParameter(aesKeyBytes),
                        ccmTagLengthBits, iv, null);
        org.bouncycastle.crypto.modes.CCMModeCipher bcEncCipher =
                org.bouncycastle.crypto.modes.CCMBlockCipher.newInstance(bcEngineB);
        bcEncCipher.init(true, bcParamsB);
        bcEncCipher.processAADBytes(aadBytes, 0, aadBytes.length);
        byte[] ciphertextB = new byte[bcEncCipher.getOutputSize(plaintext.length)];
        int bcEncLen = bcEncCipher.processBytes(plaintext, 0, plaintext.length, ciphertextB, 0);
        bcEncCipher.doFinal(ciphertextB, bcEncLen);

        // Place BC's ciphertext (36 bytes) inside a large backing array at an offset,
        // so the backing array length (100) >> the slice length (36).
        int cipherInputOffset = 32;
        int cipherInputLen    = ciphertextB.length; // 36
        byte[] cipherBacking = new byte[100];
        System.arraycopy(ciphertextB, 0, cipherBacking, cipherInputOffset, cipherInputLen);

        ibm.security.internal.spec.CCMParameterSpec ccmParamDec =
                new ibm.security.internal.spec.CCMParameterSpec(ccmTagLengthBits, iv);
        Cipher decCipherOJP = Cipher.getInstance("AES/CCM/NoPadding", getProviderName());
        decCipherOJP.init(Cipher.DECRYPT_MODE, keySpec, ccmParamDec);
        decCipherOJP.updateAAD(aadBytes);

        // Output buffer sized exactly for the decrypted plaintext: cipherInputLen - tagLenInBytes = 20.
        // Before the fix for issue #1564, this would throw a ShortBufferException
        // because the check incorrectly used input.length (100) instead of inputLen (36).
        // See: https://github.com/IBM/OpenJCEPlus/issues/1564 for more information on failing scenarios.
        int decOutputLen = cipherInputLen - tagLenInBytes; // 20
        byte[] decryptedB = new byte[decOutputLen];
        int bytesDecrypted = decCipherOJP.doFinal(cipherBacking, cipherInputOffset, cipherInputLen,
                decryptedB, 0);

        Assertions.assertEquals(plaintext.length, bytesDecrypted,
                "Scenario B: OpenJCEPlus decrypted byte count should equal original plaintext length");
        Assertions.assertArrayEquals(plaintext, decryptedB,
                "Scenario B: OpenJCEPlus-decrypted bytes must match original plaintext");
    }

    private static byte[] encrypt(byte[] plaintext, byte[] aesKeyBytes, byte[] IV, int ccmTagLength)
            throws Exception {
        synchronized (myMutexObject) {
            if (printJunitTrace)
                System.out.println(
                        "\n==========================================================================");
            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  encrypt():  *****   BEGIN ENCRYPTION METHOD  *****");
            if (printJunitTrace)
                System.out.println(
                        "==========================================================================\n");
        }

        // If the encryption provider is OpenIBMJCEPlus, then initialize the cipher with a ibm.security.internal.spec.CCMParameterSpec object
        if (encryptionProvider.equals("OpenJCEPlus")) {
            // Get Cipher Instance
            Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", encryptionProvider);
            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  encrypt():  The encryption cipher is a:                "
                                + cipher.getClass().getName());
            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  encrypt():  The provider of the encryption cipher is:  "
                                + cipher.getProvider());

            // Create SecretKeySpec
            SecretKeySpec keySpec = new SecretKeySpec(aesKeyBytes, "AES");

            // Create the ibm.security.internal.spec.CCMParameterSpec object
            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  encrypt():  The encryption tag length (in bits)  is:  "
                                + ccmTagLength);
            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  encrypt():  The encryption IV length (in bytes) is:  "
                                + IV.length);
            ibm.security.internal.spec.CCMParameterSpec ccmParameterSpec = new ibm.security.internal.spec.CCMParameterSpec(
                    ccmTagLength, IV); // ccmTagLength is specified in bits

            // Initialize Cipher for ENCRYPT_MODE
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ccmParameterSpec);

            // Initialize encryption Cipher with AAD
            cipher.updateAAD(aad);

            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  encrypt():  MAKING OCK ENCRYPTION CALL FROM encrypt() METHOD !!!");

            // Perform Encryption
            byte[] cipherText = null;
            try {
                Random randomForMethodChoice = new Random();
                int whichMethod = randomForMethodChoice.nextInt(5); // The specified value is excluded

                if (whichMethod == 0) {
                    if (printJunitTrace)
                        System.out
                                .println("BaseTestInteropBC.java:  encrypt():  METHOD CHOSEN = 0");

                    byte[] cipherText2 = cipher.doFinal(plaintext);

                    // All the encryption was performed on Cipher.doFinal( )
                    cipherText = new byte[cipherText2.length];
                    System.arraycopy(cipherText2, 0, cipherText, 0, cipherText2.length);
                } else if (whichMethod == 1) {
                    if (printJunitTrace)
                        System.out
                                .println("BaseTestInteropBC.java:  encrypt():  METHOD CHOSEN = 1");

                    byte[] cipherText2 = cipher.doFinal(plaintext, 0, plaintext.length);

                    // All the encryption was performed on Cipher.doFinal( )
                    cipherText = new byte[cipherText2.length];
                    System.arraycopy(cipherText2, 0, cipherText, 0, cipherText2.length);
                } else if (whichMethod == 2) {
                    if (printJunitTrace)
                        System.out
                                .println("BaseTestInteropBC.java:  encrypt():  METHOD CHOSEN = 2");
                    int outputSizeNeeded = cipher.getOutputSize(plaintext.length);
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestInteropBC.java:  encrypt():  The outputSizeNeeded is:                    "
                                        + outputSizeNeeded);

                    int outputLengthNeeded = cipher.getOutputSize(plaintext.length);
                    byte[] cipherText2 = new byte[outputLengthNeeded];
                    int cipherText2Length = cipher.doFinal(plaintext, 0, plaintext.length,
                            cipherText2);

                    if (cipherText2Length != cipherText2.length) {
                        if (printJunitTrace)
                            System.out.println(
                                    "BaseTestInteropBC.java:  encrypt():  ERROR:  cipherText2Length is not equal to cipherText2.length.  ");
                        RuntimeException rtex = new RuntimeException();
                        rtex.printStackTrace(System.out);
                        Assertions.fail();
                    }

                    // All the encryption was performed on Cipher.doFinal( )
                    cipherText = new byte[cipherText2.length];
                    System.arraycopy(cipherText2, 0, cipherText, 0, cipherText2.length);
                } else if (whichMethod == 3) {
                    if (printJunitTrace)
                        System.out
                                .println("BaseTestInteropBC.java:  encrypt():  METHOD CHOSEN = 3");
                    int outputSizeNeeded = cipher.getOutputSize(plaintext.length);
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestInteropBC.java:  encrypt():  The outputSizeNeeded is:                    "
                                        + outputSizeNeeded);

                    int outputLengthNeeded = cipher.getOutputSize(plaintext.length);
                    byte[] cipherText2 = new byte[outputLengthNeeded];
                    int cipherText2Length = cipher.doFinal(plaintext, 0, plaintext.length,
                            cipherText2, 0);

                    if (cipherText2Length != cipherText2.length) {
                        if (printJunitTrace)
                            System.out.println(
                                    "BaseTestInteropBC.java:  encrypt():  ERROR:  cipherText2Length is not equal to cipherText2.length.  ");
                        RuntimeException rtex = new RuntimeException();
                        rtex.printStackTrace(System.out);
                        Assertions.fail();
                    }

                    // All the encryption was performed on Cipher.doFinal( )
                    cipherText = new byte[cipherText2.length];
                    System.arraycopy(cipherText2, 0, cipherText, 0, cipherText2.length);
                } else if (whichMethod == 4) {
                    if (printJunitTrace)
                        System.out
                                .println("BaseTestInteropBC.java:  encrypt():  METHOD CHOSEN = 4");

                    ByteBuffer byteBuffer1 = ByteBuffer.allocate(plaintext.length);
                    byteBuffer1.put(plaintext);
                    int outputSizeNeeded = cipher.getOutputSize(plaintext.length);
                    ByteBuffer byteBuffer2 = ByteBuffer.allocate(outputSizeNeeded);

                    byteBuffer1 = ByteBuffer.allocate(plaintext.length);
                    byteBuffer1.put(plaintext);
                    outputSizeNeeded = cipher.getOutputSize(plaintext.length);
                    byteBuffer2 = ByteBuffer.allocate(outputSizeNeeded);
                    int cipherText2Length = cipher.doFinal(byteBuffer1, byteBuffer2);
                    byte[] cipherText2 = byteBuffer2.array();

                    if (cipherText2Length != cipherText2.length) {
                        if (printJunitTrace)
                            System.out.println(
                                    "BaseTestInteropBC.java:  encrypt():  ERROR:  cipherText2Length is not equal to cipherText2.length.  ");
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
                            "BaseTestInteropBC.java:  encrypt():  ERROR:  The following exception was thrown.  ");
                ex.printStackTrace(System.out);
                Assertions.fail();
            }

            if (printJunitTrace)
                System.out.println("BaseTestInteropBC.java:  encrypt():  The encrypted bytes are:");
            if (printJunitTrace)
                System.out.println(toHexString(cipherText) + "\n");

            synchronized (myMutexObject) {
                if (printJunitTrace)
                    System.out.println(
                            "\n==========================================================================");
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestInteropBC.java:  encrypt():  *****   END ENCRYPTION METHOD    *****");
                if (printJunitTrace)
                    System.out.println(
                            "==========================================================================\n");
            }

            return cipherText;

        } else { // else if the encryption provider is "BC".
            // AES/CCM for BouncyCastle is a proprietary cipher implementation that
            // is dissimilar to cipher implementations developed by Oracle or IBM.

            if (printJunitTrace) {
                System.out.println("\nThe plain text to be encoded is:");
                System.out.println(toHexString(plaintext));
            }

            org.bouncycastle.crypto.MultiBlockCipher engine = org.bouncycastle.crypto.engines.AESEngine.newInstance();
            org.bouncycastle.crypto.params.AEADParameters params = new org.bouncycastle.crypto.params.AEADParameters(
                    new org.bouncycastle.crypto.params.KeyParameter(aesKeyBytes), ccmTagLength, IV,
                    null);

            org.bouncycastle.crypto.modes.CCMModeCipher cipher = org.bouncycastle.crypto.modes.CCMBlockCipher.newInstance(
                    engine);
            cipher.init(true, params); // true for encryption
            byte[] cipherText = new byte[cipher.getOutputSize(plaintext.length)];
            int cipherTextLen = cipher.processBytes(plaintext, 0, plaintext.length, cipherText, 0);
            cipher.processAADBytes(aad, 0, aad.length);
            cipher.doFinal(cipherText, cipherTextLen);

            // cipherText and mac are in bytes
            if (printJunitTrace)
                System.out.println("\nThe cipherText is:");
            if (printJunitTrace)
                System.out.println(toHexString(cipherText));
            if (printJunitTrace)
                System.out.println("\nThe mac is:");
            if (printJunitTrace)
                System.out.println(toHexString(cipher.getMac()));

            synchronized (myMutexObject) {
                if (printJunitTrace)
                    System.out.println(
                            "\n==========================================================================");
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestInteropBC.java:  encrypt():  *****   END ENCRYPTION METHOD    *****");
                if (printJunitTrace)
                    System.out.println(
                            "==========================================================================\n");
            }

            return cipherText;
        }

    } // end encrypt( )



    private static String decrypt(byte[] cipherText, byte[] aesKeyBytes, byte[] IV,
            int ccmTagLength) throws Exception {
        synchronized (myMutexObject) {
            if (printJunitTrace)
                System.out.println(
                        "\n==========================================================================");
            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  decrypt():  *****   BEGIN DECRYPTION METHOD  *****");
            if (printJunitTrace)
                System.out.println(
                        "==========================================================================\n");
        }

        // If the decryption provider is IBMJCEPlus, then initialize the cipher with a ibm.security.internal.spec.CCMParameterSpec object
        if (decryptionProvider.equals("OpenJCEPlus")) {
            // Get Cipher Instance
            Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", decryptionProvider);
            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  decrypt():  The decryption cipher is a:                "
                                + cipher.getClass().getName());
            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  decrypt():  The provider of the decryption cipher is:  "
                                + cipher.getProvider());

            // Create SecretKeySpec
            SecretKeySpec keySpec = new SecretKeySpec(aesKeyBytes, "AES");

            // Create the ibm.security.internal.spec.CCMParameterSpec object
            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  decrypt():  The decryption tag length (in bits)  is:  "
                                + ccmTagLength);
            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  decrypt():  The decryption IV length (in bytes) is:  "
                                + IV.length);
            ibm.security.internal.spec.CCMParameterSpec ccmParameterSpec = new ibm.security.internal.spec.CCMParameterSpec(
                    ccmTagLength, IV); // ccmTagLength is specified in bits

            // Initialize Cipher for DECRYPT_MODE
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ccmParameterSpec);

            // Initialize decryption Cipher with AAD
            cipher.updateAAD(aad);

            if (printJunitTrace)
                System.out.println(
                        "BaseTestInteropBC.java:  decrypt():  MAKING OCK DECRYPTION CALL FROM decrypt() METHOD !!!");

            // Perform Decryption
            byte[] decryptedText = null;
            try {
                Random randomForMethodChoice = new Random();
                int whichMethod = randomForMethodChoice.nextInt(5); // The specified value is excluded

                if (whichMethod == 0) {
                    if (printJunitTrace)
                        System.out
                                .println("BaseTestInteropBC.java:  decrypt():  METHOD CHOSEN = 0");

                    // Decrypt the cipherText

                    byte[] decryptedText2 = cipher.doFinal(cipherText);

                    // All the decryption was performed on Cipher.doFinal( )
                    decryptedText = new byte[decryptedText2.length];
                    System.arraycopy(decryptedText2, 0, decryptedText, 0, decryptedText2.length);
                } else if (whichMethod == 1) {
                    if (printJunitTrace)
                        System.out
                                .println("BaseTestInteropBC.java:  decrypt():  METHOD CHOSEN = 1");

                    // Decrypt the cipherText

                    byte[] decryptedText2 = cipher.doFinal(cipherText, 0, cipherText.length);

                    // All the decryption was performed on Cipher.doFinal( )
                    decryptedText = new byte[decryptedText2.length];
                    System.arraycopy(decryptedText2, 0, decryptedText, 0, decryptedText2.length);
                } else if (whichMethod == 2) {
                    if (printJunitTrace)
                        System.out
                                .println("BaseTestInteropBC.java:  decrypt():  METHOD CHOSEN = 2");
                    int outputSizeNeeded = cipher.getOutputSize(cipherText.length);
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestInteropBC.java:  decrypt():  The outputSizeNeeded is:                    "
                                        + outputSizeNeeded);

                    outputSizeNeeded = cipher.getOutputSize(cipherText.length);
                    byte[] decryptedText2 = new byte[outputSizeNeeded];
                    int decryptedText2Length = cipher.doFinal(cipherText, 0, cipherText.length,
                            decryptedText2);

                    if (decryptedText2Length != decryptedText2.length) {
                        if (printJunitTrace)
                            System.out.println(
                                    "BaseTestInteropBC.java:  decrypt():  ERROR:  decryptedText2Length is not equal to decryptedText2.length.  ");
                        RuntimeException rtex = new RuntimeException();
                        rtex.printStackTrace(System.out);
                        Assertions.fail();
                    }

                    // All the decryption was performed on Cipher.doFinal( )
                    decryptedText = new byte[decryptedText2.length];
                    System.arraycopy(decryptedText2, 0, decryptedText, 0, decryptedText2.length);
                } else if (whichMethod == 3) {
                    if (printJunitTrace) {
                        System.out.println("BaseTestInteropBC.java:  decrypt():  METHOD CHOSEN = 3");
                    }
                    int outputSizeNeeded = cipher.getOutputSize(cipherText.length);
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestInteropBC.java:  decrypt():  The outputSizeNeeded is:                    "
                                        + outputSizeNeeded);

                    outputSizeNeeded = cipher.getOutputSize(cipherText.length);
                    byte[] decryptedText2 = new byte[outputSizeNeeded];
                    int decryptedText2Length = cipher.doFinal(cipherText, 0, cipherText.length,
                            decryptedText2, 0);

                    if (decryptedText2Length != decryptedText2.length) {
                        if (printJunitTrace)
                            System.out.println(
                                    "BaseTestInteropBC.java:  decrypt():  ERROR:  decryptedText2Length is not equal to decryptedText2.length.  ");
                        RuntimeException rtex = new RuntimeException();
                        rtex.printStackTrace(System.out);
                        Assertions.fail();
                    }

                    // All the decryption was performed on Cipher.doFinal( )
                    decryptedText = new byte[decryptedText2.length];
                    System.arraycopy(decryptedText2, 0, decryptedText, 0, decryptedText2.length);
                } else if (whichMethod == 4) {
                    if (printJunitTrace)
                        System.out
                                .println("BaseTestInteropBC.java:  decrypt():  METHOD CHOSEN = 4");
                    int outputSizeNeeded = cipher.getOutputSize(cipherText.length);
                    if (printJunitTrace)
                        System.out.println(
                                "BaseTestInteropBC.java:  decrypt():  The outputSizeNeeded is:                    "
                                        + outputSizeNeeded);

                    ByteBuffer byteBuffer1 = ByteBuffer.allocate(cipherText.length);
                    byteBuffer1.put(cipherText);

                    ByteBuffer byteBuffer2 = ByteBuffer.allocate(outputSizeNeeded);

                    int decryptedText2Length = cipher.doFinal(byteBuffer1, byteBuffer2);
                    byte[] decryptedText2 = byteBuffer2.array();

                    if (decryptedText2Length != decryptedText2.length) {
                        if (printJunitTrace)
                            System.out.println(
                                    "BaseTestInteropBC.java:  decrypt():  ERROR:  decryptedText2Length is not equal to decryptedText2.length.  ");
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
                            "BaseTestInteropBC.java:  decrypt():  ERROR:  The following AEADBadTagException was thrown on the cipher.doFinal() call.");
                abte.printStackTrace(System.out);
                Assertions.fail();
            } catch (Exception ex) {
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestInteropBC.java:  decrypt():  ERROR:  The following exception was thrown.  ");
                ex.printStackTrace(System.out);
                Assertions.fail();
            }

            synchronized (myMutexObject) {
                if (printJunitTrace)
                    System.out.println(
                            "\n==========================================================================");
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestInteropBC.java:  decrypt():  *****    END DECRYPTION METHOD   *****");
                if (printJunitTrace)
                    System.out.println(
                            "==========================================================================\n");
            }

            return new String(decryptedText);

        } else { // else if the decryption provider is "BC".
            // AES/CCM for BouncyCastle is a proprietary cipher implementation that
            // is dissimilar to cipher implementations developed by Oracle or IBM.

            if (printJunitTrace)
                System.out.println("\nThe cipherText to be decoded is:");
            if (printJunitTrace)
                System.out.println(toHexString(cipherText));

            org.bouncycastle.crypto.BlockCipher engine = org.bouncycastle.crypto.engines.AESEngine.newInstance();
            org.bouncycastle.crypto.params.AEADParameters params = new org.bouncycastle.crypto.params.AEADParameters(
                    new org.bouncycastle.crypto.params.KeyParameter(aesKeyBytes), ccmTagLength, IV,
                    null);

            org.bouncycastle.crypto.modes.CCMModeCipher cipher = org.bouncycastle.crypto.modes.CCMBlockCipher.newInstance(
                    engine);
            cipher.init(false, params); // false for decryption
            byte[] decryptedText = new byte[cipher.getOutputSize(cipherText.length)];
            int decryptedTextLen = cipher.processBytes(cipherText, 0, cipherText.length,
                    decryptedText, 0);
            cipher.processAADBytes(aad, 0, aad.length);
            cipher.doFinal(decryptedText, decryptedTextLen);

            // decryptedText and mac are in bytes
            if (printJunitTrace)
                System.out.println("\nThe decryptedText is:");
            if (printJunitTrace)
                System.out.println(toHexString(decryptedText));
            if (printJunitTrace)
                System.out.println("\nThe mac is:");
            if (printJunitTrace)
                System.out.println(toHexString(cipher.getMac()));

            synchronized (myMutexObject) {
                if (printJunitTrace)
                    System.out.println(
                            "\n==========================================================================");
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestInteropBC.java:  decrypt():  *****    END DECRYPTION METHOD   *****");
                if (printJunitTrace)
                    System.out.println(
                            "==========================================================================\n");
            }

            return new String(decryptedText);
        }

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
