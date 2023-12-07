/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

/*
 *  A test program to test AES-GCM Internal IV generation scenarios.
 */

package ibm.jceplus.junit.base;

import java.lang.reflect.Constructor;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class BaseTestAESGCM_IntIV extends BaseTest {

    private static final int DEFAULT_TAG_LENGTH = 128;

    // --------------------------------------------------------------------------
    //
    //
    private final static String RUN_FULL_TEST_SUITE = System.getProperty("run_full_test_suite",
            "false");

    static final byte[] plainTextEncrypt = "1234567812345678123456781234567812345678123456781234567812345678"
            .getBytes();

    public static final String GENERATED_IV_MAX_INVOCATIONS_PLUS_ONE = "18446744073709551616";

    // --------------------------------------------------------------------------
    //
    //
    KeyGenerator aesKeyGen;
    SecretKey key;
    int tagLength = 16;
    AlgorithmParameterSpec aParamSpec = null;
    AlgorithmParameters aParams = null;
    Class classGCMParameterSpec = null;
    Constructor ctorGCMParameterSpec = null;

    // --------------------------------------------------------------------------
    //
    //
    public BaseTestAESGCM_IntIV(String providerName) {
        super(providerName);
    }

    // --------------------------------------------------------------------------
    //
    //
    protected void setUp() throws Exception {

        aesKeyGen = KeyGenerator.getInstance("AES", providerName);

        key = aesKeyGen.generateKey();

        /*
         * Try constructing a javax.crypto.spec.GCMParameterSpec instance (Java
         * 7+)
         */

        try {
            classGCMParameterSpec = Class.forName("javax.crypto.spec.GCMParameterSpec");
            ctorGCMParameterSpec = classGCMParameterSpec
                    .getConstructor(new Class[] {int.class, byte[].class});
        } catch (Exception e) {
            /*
             * Differ to "System.out.println("Unexpected exception: ");", below
             */
        }

        /*
         * Try constructing an ibm.security.internal.spec.GCMParameterSpec
         * instance (IBM Java 6)
         */

        if (ctorGCMParameterSpec == null) {
            try {
                classGCMParameterSpec = Class
                        .forName("ibm.security.internal.spec.GCMParameterSpec");
                ctorGCMParameterSpec = classGCMParameterSpec
                        .getConstructor(new Class[] {int.class, byte[].class});
            } catch (Exception e) {
                /*
                 * Differ to "System.out.println("Unexpected exception: ");",
                 * below
                 */
            }
        }

        byte[] iv = new byte[16];// com.ibm.crypto.plus.provider.AESConstants.AES_BLOCK_SIZE];
        SecureRandom rnd = new java.security.SecureRandom();
        rnd.nextBytes(iv);

        aParamSpec = (AlgorithmParameterSpec) ctorGCMParameterSpec.newInstance(DEFAULT_TAG_LENGTH,
                iv);
        aParams = AlgorithmParameters.getInstance("AESGCM", providerName);
        aParams.init(aParamSpec);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testAESGCM_IntIV_Test01() throws Exception {

        /* Do the encrypt using the internally generated IV */

        Cipher cipherEncrypt = Cipher.getInstance("AES/GCM/NoPadding", providerName);

        cipherEncrypt.init(Cipher.ENCRYPT_MODE, key);

        byte[] cipherTextPlusT = new byte[plainTextEncrypt.length + tagLength];
        cipherEncrypt.doFinal(plainTextEncrypt, 0, plainTextEncrypt.length, cipherTextPlusT, 0);

        /* Save the algorithm parameters used to do the encryption */

        AlgorithmParameters ap = cipherEncrypt.getParameters();

        /* Do the decryption using the internally generated IV */

        Cipher cipherDecrypt = Cipher.getInstance("AES/GCM/NoPadding", providerName);
        cipherDecrypt.init(Cipher.DECRYPT_MODE, key, ap);

        byte[] plainTextDecrypt = new byte[plainTextEncrypt.length];
        cipherDecrypt.doFinal(cipherTextPlusT, 0, cipherTextPlusT.length, plainTextDecrypt, 0);

        assertTrue("Plaintext did not match expected",
                Arrays.equals(plainTextEncrypt, plainTextDecrypt));
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testAESGCM_IntIV_Test02() throws Exception {

        /*
         * Do the encrypt using a mixture of external and internally
         * generated IVs
         */

        Cipher cipherEncrypt = Cipher.getInstance("AES/GCM/NoPadding", providerName);

        for (int i = 1; i < 6; i++) {

            if (i == 1 || i == 3 || i == 5) {
                cipherEncrypt.init(Cipher.ENCRYPT_MODE, key);
            } else if (i == 2) {
                cipherEncrypt.init(Cipher.ENCRYPT_MODE, key, aParams);
            } else /* i == 4 */ {
                cipherEncrypt.init(Cipher.ENCRYPT_MODE, key, aParamSpec);
            }

            byte[] cipherTextPlusT = new byte[plainTextEncrypt.length + tagLength];

            cipherEncrypt.doFinal(plainTextEncrypt, 0, plainTextEncrypt.length, cipherTextPlusT, 0);

            /* Save the algorithm parameters used to do the encryption */

            AlgorithmParameters ap = cipherEncrypt.getParameters();

            /* Do the decryption using the internally generated IV */

            Cipher cipherDecrypt = Cipher.getInstance("AES/GCM/NoPadding", providerName);
            cipherDecrypt.init(Cipher.DECRYPT_MODE, key, ap);

            byte[] plainTextDecrypt = new byte[plainTextEncrypt.length];
            cipherDecrypt.doFinal(cipherTextPlusT, 0, cipherTextPlusT.length, plainTextDecrypt, 0);

            assertTrue("Plaintext did not match expected",
                    Arrays.equals(plainTextEncrypt, plainTextDecrypt));
        }
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testAESGCM_IntIV_Test03() throws Exception {

        /* Do the encrypt using the internally generated IV */

        Cipher cipherEncrypt = Cipher.getInstance("AES/GCM/NoPadding", providerName);

        cipherEncrypt.init(Cipher.ENCRYPT_MODE, key, (AlgorithmParameters) null);

        byte[] cipherTextPlusT = new byte[plainTextEncrypt.length + tagLength];

        cipherEncrypt.doFinal(plainTextEncrypt, 0, plainTextEncrypt.length, cipherTextPlusT, 0);

        /* Save the algorithm parameters used to do the encryption */

        AlgorithmParameters ap = cipherEncrypt.getParameters();

        /* Do the decryption using the internally generated IV */

        Cipher cipherDecrypt = Cipher.getInstance("AES/GCM/NoPadding", providerName);
        cipherDecrypt.init(Cipher.DECRYPT_MODE, key, ap);

        byte[] plainTextDecrypt = new byte[plainTextEncrypt.length];
        cipherDecrypt.doFinal(cipherTextPlusT, 0, cipherTextPlusT.length, plainTextDecrypt, 0);

        assertTrue("Plaintext did not match expected",
                Arrays.equals(plainTextEncrypt, plainTextDecrypt));
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testAESGCM_IntIV_Test04() throws Exception {

        /* Do the encrypt using the internally generated IV */

        Cipher cipherEncrypt = Cipher.getInstance("AES/GCM/NoPadding", providerName);

        cipherEncrypt.init(Cipher.ENCRYPT_MODE, key, (AlgorithmParameterSpec) null);

        byte[] cipherTextPlusT = new byte[plainTextEncrypt.length + tagLength];

        cipherEncrypt.doFinal(plainTextEncrypt, 0, plainTextEncrypt.length, cipherTextPlusT, 0);

        /* Save the algorithm parameters used to do the encryption */

        AlgorithmParameters ap = cipherEncrypt.getParameters();
        AlgorithmParameterSpec apSpec = ap.getParameterSpec(classGCMParameterSpec);

        /* Do the decryption using the internally generated IV */

        Cipher cipherDecrypt = Cipher.getInstance("AES/GCM/NoPadding", providerName);
        cipherDecrypt.init(Cipher.DECRYPT_MODE, key, apSpec);

        byte[] plainTextDecrypt = new byte[plainTextEncrypt.length];
        cipherDecrypt.doFinal(cipherTextPlusT, 0, cipherTextPlusT.length, plainTextDecrypt, 0);

        assertTrue("Plaintext did not match expected",
                Arrays.equals(plainTextEncrypt, plainTextDecrypt));
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testAESGCM_IntIV_Test05() throws Exception {

        try {
            /* Do the encrypt using the internally generated IV */

            Cipher cipherEncrypt = Cipher.getInstance("AES/GCM/NoPadding", providerName);

            cipherEncrypt.init(Cipher.ENCRYPT_MODE, key, (AlgorithmParameters) null);

            byte[] cipherTextPlusT = new byte[plainTextEncrypt.length + tagLength];

            cipherEncrypt.doFinal(plainTextEncrypt, 0, plainTextEncrypt.length, cipherTextPlusT, 0);

            /* Do the decryption using the internally generated IV */

            Cipher cipherDecrypt = Cipher.getInstance("AES/GCM/NoPadding", providerName);
            cipherDecrypt.init(Cipher.DECRYPT_MODE, key);

            byte[] plainTextDecrypt = new byte[plainTextEncrypt.length];
            cipherDecrypt.doFinal(cipherTextPlusT, 0, cipherTextPlusT.length, plainTextDecrypt, 0);
        } catch (InvalidKeyException ex) {
            assertTrue("Got expected invalid key exception", true);
        } catch (RuntimeException rte) {
            assertTrue("Got expected exception", true);
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getMessage());
        }
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testAESGCM_IntIV_Test06() throws Exception {

        try {
            /* Do the encrypt using the internally generated IV */

            Cipher cipherEncrypt = Cipher.getInstance("AES/GCM/NoPadding", providerName);

            cipherEncrypt.init(Cipher.ENCRYPT_MODE, key, (AlgorithmParameters) null);

            byte[] cipherTextPlusT = new byte[plainTextEncrypt.length + tagLength];

            cipherEncrypt.doFinal(plainTextEncrypt, 0, plainTextEncrypt.length, cipherTextPlusT, 0);

            /* Do the decryption using the internally generated IV */

            Cipher cipherDecrypt = Cipher.getInstance("AES/GCM/NoPadding", providerName);
            cipherDecrypt.init(Cipher.DECRYPT_MODE, key, (AlgorithmParameters) null);

            byte[] plainTextDecrypt = new byte[plainTextEncrypt.length];
            cipherDecrypt.doFinal(cipherTextPlusT, 0, cipherTextPlusT.length, plainTextDecrypt, 0);

        } catch (InvalidAlgorithmParameterException ipe) {
            assertTrue("Got expected exception", true);
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getMessage());
        }
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testAESGCM_IntIV_Test07() throws Exception {

        try {
            /* Do the encrypt using the internally generated IV */

            Cipher cipherEncrypt = Cipher.getInstance("AES/GCM/NoPadding", providerName);

            cipherEncrypt.init(Cipher.ENCRYPT_MODE, key, (AlgorithmParameterSpec) null);

            byte[] cipherTextPlusT = new byte[plainTextEncrypt.length + tagLength];

            cipherEncrypt.doFinal(plainTextEncrypt, 0, plainTextEncrypt.length, cipherTextPlusT, 0);

            /* Do the decryption using the internally generated IV */

            Cipher cipherDecrypt = Cipher.getInstance("AES/GCM/NoPadding", providerName);
            cipherDecrypt.init(Cipher.DECRYPT_MODE, key, (AlgorithmParameterSpec) null);

            byte[] plainTextDecrypt = new byte[plainTextEncrypt.length];
            cipherDecrypt.doFinal(cipherTextPlusT, 0, cipherTextPlusT.length, plainTextDecrypt, 0);

        } catch (InvalidAlgorithmParameterException ipe) {
            assertTrue("Got expected exception", true);
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getMessage());
        }
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testAESGCM_IntIV_Test08() throws Exception {

        //Assume.assumeTrue(RUN_FULL_TEST_SUITE.equals("true"));
        if (!RUN_FULL_TEST_SUITE.equals("true")) {
            assertTrue("Test skipped", true);
            return;
        }

        try {

            /*
             * Test maximum invocations checking for the same key and internally
             * generated IV
             */

            Cipher cipherEncrypt = Cipher.getInstance("AES/GCM/NoPadding", providerName);

            cipherEncrypt.init(Cipher.ENCRYPT_MODE, key);

            BigInteger max_inv_plus_one = new BigInteger(GENERATED_IV_MAX_INVOCATIONS_PLUS_ONE);
            BigInteger inv = new BigInteger("1");

            for (; inv.compareTo(max_inv_plus_one) < 1; inv = inv.add(BigInteger.ONE)) {

                byte[] cipherTextPlusT = new byte[plainTextEncrypt.length + tagLength];

                cipherEncrypt.doFinal(plainTextEncrypt, 0, plainTextEncrypt.length, cipherTextPlusT,
                        0);

                /* Save the algorithm parameters used to do the encryption */

                AlgorithmParameters ap = cipherEncrypt.getParameters();

                /* Do the decryption using the internally generated IV */

                Cipher cipherDecrypt = Cipher.getInstance("AES/GCM/NoPadding", providerName);
                cipherDecrypt.init(Cipher.DECRYPT_MODE, key, ap);

                byte[] plainTextDecrypt = new byte[plainTextEncrypt.length];
                cipherDecrypt.doFinal(cipherTextPlusT, 0, cipherTextPlusT.length, plainTextDecrypt,
                        0);
            }

        } catch (IllegalStateException ise) {
            assertTrue("Got expected exception", true);
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getMessage());
        }
    }

    /*
     * Checks if the given portion of b1 and b2 are equal.
     * 
     * @return true if they are equal, false if they are not equal or if the specified offsets and lengths are out of bounds. 
     */
    private boolean byteEqual(byte[] b1, int offset1, byte[] b2, int offset2, int len) {
        if ((b1.length - offset1) >= len && (b2.length - offset2) >= len) {
            for (int i = 0; i < len; i++) {
                if (b1[i + offset1] != b2[i + offset2]) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }
}
