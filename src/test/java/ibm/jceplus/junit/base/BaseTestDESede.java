/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;

public class BaseTestDESede extends BaseTestCipher {

    // 14 bytes: PASSED
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

    static final byte[] plainText = plainText128; // default value

    protected boolean supportsEncrypt;
    protected String encryptProviderName;
    protected KeyGenerator keyGen;
    protected SecretKey key;
    protected AlgorithmParameters params = null;

    /*
     * Only be used within tests that have no intentions of making use of cp.
     * Do not make use of this field with tests that are making use of cp for
     * multithreaded testing of this cipher.
     */
    protected Cipher cp = null;

    public BaseTestDESede(String providerName) {
        this(providerName, true);
    }

    public BaseTestDESede(String providerName, boolean supportsEncrypt) {
        super(providerName);
        this.supportsEncrypt = supportsEncrypt;
        this.encryptProviderName = supportsEncrypt ? providerName : "IBMJCE";
    }

    public void setUp() throws Exception {
        try {
            keyGen = KeyGenerator.getInstance("DESede", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: DESede for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
        key = keyGen.generateKey();
    }

    public void testDESede() throws Exception {
        try {
            encryptDecrypt("DESede");
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("No such algorithm: DESede", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    public void testDESede_CBC_ISO10126Padding() throws Exception {
        try {
            cp = Cipher.getInstance("DESede/CBC/ISO10126Padding", providerName);
            fail(" NoSuchPaddingException is NOT thrown");
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("No such algorithm: DESede/CBC/ISO10126Padding", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        } catch (NoSuchPaddingException e) {
            assertTrue(true);
        }
    }

    public void testDESede_CBC_NoPadding() throws Exception {
        try {
            encryptDecrypt("DESede/CBC/NoPadding", true);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("No such algorithm: DESede/CBC/NoPadding", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    public void testDESede_CBC_PKCS5Padding() throws Exception {
        try {
            encryptDecrypt("DESede/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("No such algorithm: DESede/CBC/PKCS5Padding", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    public void testDESede_CFB_ISO10126Padding() throws Exception {
        String algorithm = "DESede/CFB/ISO10126Padding";

        if (isTransformationValidButUnsupported(algorithm)) {
            return;
        }

        try {
            cp = Cipher.getInstance(algorithm, providerName);
            fail(" NoSuchPaddingException is NOT thrown");
        } catch (NoSuchPaddingException e) {
            assertTrue(true);
        }
    }

    public void testDESede_CFB_NoPadding() throws Exception {
        encryptDecrypt("DESede/CFB/NoPadding");
    }

    public void testDESede_CFB_PKCS5Padding() throws Exception {
        encryptDecrypt("DESede/CFB/PKCS5Padding");
    }

    public void testDESede_CFB64_ISO10126Padding() throws Exception {
        String algorithm = "DESede/CFB64/ISO10126Padding";

        if (isTransformationValidButUnsupported(algorithm)) {
            return;
        }

        try {
            cp = Cipher.getInstance(algorithm, providerName);
            fail(" NoSuchPaddingException is NOT thrown");
        } catch (NoSuchPaddingException e) {
            assertTrue(true);
        }
    }

    public void testDESede_CFB64_NoPadding() throws Exception {
        encryptDecrypt("DESede/CFB64/NoPadding");
    }

    public void testDESede_CFB64_PKCS5Padding() throws Exception {
        encryptDecrypt("DESede/CFB64/PKCS5Padding");
    }

    public void testDESede_CTR_ISO10126Padding() throws Exception {
        try {
            cp = Cipher.getInstance("DESede/CTR/ISO10126Padding", providerName);
            fail(" NoSuchAlgorithmException is NOT thrown");
        } catch (NoSuchAlgorithmException e) {
        }
    }

    public void testDESede_CTR_NoPadding() throws Exception {
        try {
            cp = Cipher.getInstance("DESede/CTR/NoPadding", providerName);
            fail(" NoSuchAlgorithmException is NOT thrown");
        } catch (NoSuchAlgorithmException e) {
        }
    }

    public void testDESede_CTR_PKCS5Padding() throws Exception {
        try {
            cp = Cipher.getInstance("DESede/CTR/PKCS5Padding", providerName);
            fail(" NoSuchAlgorithmException is NOT thrown");
        } catch (NoSuchAlgorithmException e) {
        }
    }

    public void testDESede_CTS_ISO10126Padding() throws Exception {
        try {
            cp = Cipher.getInstance("DESede/CTS/ISO10126Padding", providerName);
            fail(" NoSuchAlgorithmException is NOT thrown");
        } catch (NoSuchAlgorithmException e) {
        }
    }

    public void testDESede_CTS_NoPadding() throws Exception {
        try {
            cp = Cipher.getInstance("DESede/CTS/NoPadding", providerName);
            fail(" NoSuchAlgorithmException is NOT thrown");
        } catch (NoSuchAlgorithmException e) {
        }
    }

    public void testDESede_CTS_PKCS5Padding() throws Exception {
        try {
            cp = Cipher.getInstance("DESede/CTS/PKCS5Padding", providerName);
            fail(" NoSuchAlgorithmException is NOT thrown");
        } catch (NoSuchAlgorithmException e) {
            assertTrue(true);
        }
    }

    public void testDESede_ECB_ISO10126Padding() throws Exception {
        try {
            cp = Cipher.getInstance("DESede/ECB/ISO10126Padding", providerName);
            fail(" NoSuchPaddingException is NOT thrown");
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("No such algorithm: DESede/ECB/ISO10126Padding", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        } catch (NoSuchPaddingException e) {
            assertTrue(true);
        }
    }

    public void testDESede_ECB_NoPadding() throws Exception {
        try {
            encryptDecrypt("DESede/ECB/NoPadding", true);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("No such algorithm: DESede/ECB/NoPadding", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    public void testDESede_ECB_PKCS5Padding() throws Exception {
        try {
            encryptDecrypt("DESede/ECB/PKCS5Padding");
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("No such algorithm: DESede/ECB/PKCS5Padding", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    public void testDESede_OFB_ISO10126Padding() throws Exception {
        String algorithm = "DESede/OFB/ISO10126Padding";

        if (isTransformationValidButUnsupported(algorithm)) {
            return;
        }
        try {
            cp = Cipher.getInstance(algorithm, providerName);
            fail(" NoSuchPaddingException is NOT thrown");
        } catch (NoSuchPaddingException e) {
            assertTrue(true);
        }
    }

    public void testDESede_OFB_NoPadding() throws Exception {
        encryptDecrypt("DESede/OFB/NoPadding");
    }

    public void testDESede_OFB_PKCS5Padding() throws Exception {
        encryptDecrypt("DESede/OFB/PKCS5Padding");
    }

    public void testDESede_PCBC_ISO10126Padding() throws Exception {
        try {
            cp = Cipher.getInstance("DESede/PCBC/ISO10126Padding", providerName);
            fail(" NoSuchAlgorithmException is NOT thrown");
        } catch (NoSuchAlgorithmException e) {
            assertTrue(true);
        }
    }

    public void testDESede_PCBC_NoPadding() throws Exception {
        try {
            cp = Cipher.getInstance("DESede/PCBC/NoPadding", providerName);
            fail(" NoSuchAlgorithmException is NOT thrown");
        } catch (NoSuchAlgorithmException e) {
            assertTrue(true);
        }
    }

    public void testDESede_PCBC_PKCS5Padding() throws Exception {
        try {
            cp = Cipher.getInstance("DESede/PCBC/PKCS5Padding", providerName);
            fail(" NoSuchAlgorithmException is NOT thrown");
        } catch (NoSuchAlgorithmException e) {
            assertTrue(true);
        }
    }

    public void testDESedeShortBuffer() throws Exception {
        try {
            // Test DESede Cipher
            Cipher cp = null;
            try {
                cp = Cipher.getInstance("DESede", encryptProviderName);
            } catch (NoSuchAlgorithmException nsae) {
                if (encryptProviderName.equals("OpenJCEPlusFIPS")) {
                    assertEquals("No such algorithm: DESede", nsae.getMessage());
                    return;
                } else {
                    throw nsae;
                }
            }

            // Encrypt the plain text
            cp.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = cp.doFinal(plainText);
            params = cp.getParameters();

            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText = new byte[5];
            cp.doFinal(cipherText, 0, cipherText.length, newPlainText);

            fail("Expected ShortBufferException did not occur");
        } catch (ShortBufferException ex) {
            assertTrue(true);
        }
    }

    public void testDESedeIllegalBlockSizeEncrypt() throws Exception {
        if (supportsEncrypt == false) {
            return;
        }

        try {
            Cipher cp = null;
            try {
                cp = Cipher.getInstance("DESede/CBC/NoPadding", providerName);
            } catch (NoSuchAlgorithmException nsae) {
                if (providerName.equals("OpenJCEPlusFIPS")) {
                    assertEquals("No such algorithm: DESede/CBC/NoPadding", nsae.getMessage());
                    return;
                } else {
                    throw nsae;
                }
            }

            int blockSize = cp.getBlockSize();
            byte[] message = new byte[blockSize - 1];

            // Encrypt the plain text
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(message);

            fail("Expected IllegalBlockSizeException did not occur");

        } catch (IllegalBlockSizeException ex) {
            assertTrue(true);
        }
    }

    public void testDESedeIllegalBlockSizeDecrypt() throws Exception {
        try {
            Cipher cp = null;
            try {
                cp = Cipher.getInstance("DESede/CBC/PKCS5Padding", encryptProviderName);
            } catch (NoSuchAlgorithmException nsae) {
                if (encryptProviderName.equals("OpenJCEPlusFIPS")) {
                    assertEquals("No such algorithm: DESede/CBC/PKCS5Padding", nsae.getMessage());
                    return;
                } else {
                    throw nsae;
                }
            }

            // Encrypt the plain text
            cp.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = cp.doFinal(plainText);
            params = cp.getParameters();

            // Verify the text
            cp = Cipher.getInstance("DESede/CBC/PKCS5Padding", providerName);
            cp.init(Cipher.DECRYPT_MODE, key, params);
            cp.doFinal(cipherText, 0, cipherText.length - 1);

            fail("Expected IllegalBlockSizeException did not occur");
        } catch (IllegalBlockSizeException ex) {
            assertTrue(true);
        }
    }

    public void testDESedeNoSuchAlgorithm() throws Exception {
        try {
            cp = Cipher.getInstance("DESede/BBC/PKCS5Padding", providerName);
            fail("Expected NoSuchAlgorithmException did not occur");
        } catch (NoSuchAlgorithmException ex) {
            assertTrue(true);
        }
    }

    public void testDESedeNull() throws Exception {
        Cipher cp = null;
        try {
            cp = Cipher.getInstance("DESede", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (encryptProviderName.equals("OpenJCEPlusFIPS")) {
                assertEquals("No such algorithm: DESede", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }

        SecretKey nullKey = null;

        try {
            cp.init(Cipher.ENCRYPT_MODE, nullKey);
            fail("Expected InvalidKeyException did not occur");
        } catch (InvalidKeyException e) {
        }

        try {
            //cp.init(Cipher.ENCRYPT_MODE, nullKey, SecureRandom.getInstance("IBMSecureRandom"));
            cp.init(Cipher.ENCRYPT_MODE, nullKey, SecureRandom.getInstance("SHA2DRBG"));
            fail("Expected InvalidKeyException did not occur");
        } catch (InvalidKeyException e) {
        }
    }

    public void testIllegalParamSpec() throws Exception {
        Cipher cp = null;
        try {
            cp = Cipher.getInstance("DESede/CBC/PKCS5Padding", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("No such algorithm: DESede/CBC/PKCS5Padding", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }

        try {
            byte[] iv = null;
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cp.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            fail("Expected NullPointerException or InvalidAlgorithmParameterException");
        } catch (NullPointerException npe) {
        } catch (InvalidAlgorithmParameterException e) {
        }

        try {
            byte[] iv = {0, 1, 2, 3, 4, 5, 6};
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cp.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            fail("Expected InvalidAlgorithmParameterException");
        } catch (InvalidAlgorithmParameterException e) {
        }

        try {
            byte[] iv = {0, 1, 2, 3, 4, 5, 6, 7, 8};
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cp.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            fail("Expected InvalidAlgorithmParameterException");
        } catch (InvalidAlgorithmParameterException e) {
        }

        try {
            byte[] iv = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cp.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            fail("Got unexpected InvalidAlgorithmParameterException");
        } catch (InvalidAlgorithmParameterException e) {
        }

        try {
            byte[] iv = {0, 1, 2, 3, 4, 5, 6, 7};
            RC5ParameterSpec ivSpec = new RC5ParameterSpec(0, 0, 0, iv);
            cp.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            fail("Expected InvalidAlgorithmParameterException");
        } catch (InvalidAlgorithmParameterException e) {
        }

        try {
            int iv = 8;
            RC2ParameterSpec ivSpec = new RC2ParameterSpec(iv);
            cp.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            fail("Expected InvalidAlgorithmParameterException");
        } catch (InvalidAlgorithmParameterException e) {
        }
    }

    public void testArgumentsDecrypt() throws Exception {
        Cipher cp = null;
        try {
            cp = Cipher.getInstance("DESede", encryptProviderName);
        } catch (NoSuchAlgorithmException nsae) {
            if (encryptProviderName.equals("OpenJCEPlusFIPS")) {
                assertEquals("No such algorithm: DESede", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }

        // Encrypt the plain text
        cp.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cp.doFinal(plainText);
        params = cp.getParameters();

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key, params);
            cp.doFinal(null);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key, params);
            cp.doFinal(new byte[0]);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key, params);
            cp.doFinal(null, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key, params);
            cp.doFinal(null, 1);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(cipherText);
            cp.doFinal(new byte[0], 0);
            fail("Did not get expected ShortBufferException on doFinal(new byte[0], 0)");
        } catch (ShortBufferException e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.doFinal(new byte[0], 1);
            fail("Should have gotten exception on doFinal(new byte[0], 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(cipherText);
            cp.doFinal(new byte[cp.getOutputSize(0)], 1);
            fail("Expected ShortBufferException");
        } catch (ShortBufferException e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.doFinal(null, 0, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.doFinal(null, 1, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.doFinal(null, 0, 1);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(cipherText);
            cp.doFinal(new byte[0], 0, 0);
        } catch (Exception e) {
            fail("Got unexpected exception on doFinal(new byte[0], 0, 0)");
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.doFinal(new byte[0], 1, 0);
            fail("Did not get expected exception on doFinal(new byte[0], 1, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 1);
            fail("Did not get expected exception on doFinal(new byte[0], 0, 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.doFinal(null, 0, 0, null);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(cipherText);
            cp.doFinal(new byte[0], 0, 0, new byte[0]);
            fail("Did not get expected ShortBufferException on doFinal(new byte[0], 0, 9, new byte[0])");
        } catch (ShortBufferException e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0, null, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(cipherText);
            cp.doFinal(new byte[0], 0, 0, new byte[0], 0);
            fail("Did not get expected ShortBufferException on doFinal(new byte[0], 0, 0, new byte[0], 0)");
        } catch (ShortBufferException e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(null);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(new byte[0]);
        } catch (Exception e) {
            fail("Got unexpected exception on update( new byte[0])");
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(null, 0, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(null, 1, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(null, 0, 1);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(new byte[0], 0, 0);
        } catch (Exception e) {
            fail("Got unexpected exception on update(new byte[0], 0, 0)");
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(new byte[0], 1, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(new byte[0], 0, 1);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(null, 0, 0, null);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(null, 0, 0, new byte[0]);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, new byte[0]);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null, 1);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.DECRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, new byte[0], 0);
        } catch (Exception e) {
        }
    }

    public void testArgumentsEncrypt() throws Exception {
        if (supportsEncrypt == false) {
            return;
        }
        Cipher cp = null;
        try {
            try {
                cp = Cipher.getInstance("DESede", providerName);
            } catch (NoSuchAlgorithmException nsae) {
                if (providerName.equals("OpenJCEPlusFIPS")) {
                    assertEquals("No such algorithm: DESede", nsae.getMessage());
                    return;
                } else {
                    throw nsae;
                }
            }
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0]);
        } catch (Exception e) {
            fail("Did not expect exception on doFinal(new byte[0], 0, 0)");
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 1);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0);
            fail("Did not get expected ShortBufferException on doFinal(new byte[0], 0)");
        } catch (ShortBufferException e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 1);
            fail("Should have gotten exception on doFinal(new byte[0], 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[cp.getOutputSize(0)], 1);
            fail("Expected ShortBufferException");
        } catch (ShortBufferException e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 1, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0, 1);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0);
        } catch (Exception e) {
            fail("Got unexpected exception on doFinal(new byte[0], 0, 0)");
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 1, 0);
            fail("Did not get expected exception on doFinal(new byte[0], 1, 0)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 1);
            fail("Did not get expected exception on doFinal(new byte[0], 0, 1)");
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(null, 0, 0, null);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0, new byte[0]);
            fail("Did not get expected ShortBufferException on doFinal(new byte[0], 0, 9, new byte[0])");
        } catch (ShortBufferException e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0, null, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.doFinal(new byte[0], 0, 0, new byte[0], 0);
            fail("Did not get expected ShortBufferException on doFinal(new byte[0], 0, 0, new byte[0], 0)");
        } catch (ShortBufferException e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0]);
        } catch (Exception e) {
            fail("Got unexpected exception on update( new byte[0])");
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 1, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 1);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0);
        } catch (Exception e) {
            fail("Got unexpected exception on update(new byte[0], 0, 0)");
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 1, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 1);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 0, null);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(null, 0, 0, new byte[0]);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, new byte[0]);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null, 0);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, null, 1);
        } catch (Exception e) {
        }

        try {
            cp = Cipher.getInstance("DESede", providerName);
            cp.init(Cipher.ENCRYPT_MODE, key);
            cp.update(new byte[0], 0, 0, new byte[0], 0);
        } catch (Exception e) {
        }
    }

    protected boolean encryptDecrypt(Cipher cp) throws Exception {
        cp.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cp.doFinal(plainText);
        params = cp.getParameters();

        // Verify the text
        cp.init(Cipher.DECRYPT_MODE, key, params);
        byte[] newPlainText = cp.doFinal(cipherText, 0, cipherText.length);

        return Arrays.equals(plainText, newPlainText);
    }

    protected void encryptDecrypt(String algorithm) throws Exception {
        encryptDecrypt(algorithm, false);
    }

    protected void encryptDecrypt(String algorithm, boolean requireLengthMultipleBlockSize)
            throws Exception {
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, null);
    }

    protected void encryptDecrypt(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams) throws Exception {
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText14);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText16);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText18);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText63);
        encryptDecrypt(algorithm, requireLengthMultipleBlockSize, algParams, plainText128);
    }

    protected void encryptDecrypt(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams, byte[] message) throws Exception {
        encryptDecryptDoFinal(algorithm, requireLengthMultipleBlockSize, algParams, message);
        encryptDecryptUpdate(algorithm, requireLengthMultipleBlockSize, algParams, message);
        encryptDecryptPartialUpdate(algorithm, requireLengthMultipleBlockSize, algParams, message);
        encryptDecryptReuseObject(algorithm, requireLengthMultipleBlockSize, algParams, message);
        encryptDecryptDoFinalCopySafe(algorithm, requireLengthMultipleBlockSize, algParams,
                message);
        encryptDecryptUpdateCopySafe(algorithm, requireLengthMultipleBlockSize, algParams, message);
    }

    protected void encryptDecryptDoFinal(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams, byte[] message) throws Exception

    {
        if (isTransformationValidButUnsupported(algorithm)) {
            return;
        }

        Cipher cp = Cipher.getInstance(algorithm, encryptProviderName);
        if (algParams == null) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cp.getBlockSize();
        try {
            byte[] cipherText = cp.doFinal(message);
            params = cp.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length,
                        ((blockSize > 0) && (message.length % blockSize) == 0));
            }

            // Verify the text
            if (providerName.equals(encryptProviderName) == false) {
                cp = Cipher.getInstance(algorithm, providerName);
            }
            cp.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText = cp.doFinal(cipherText);

            boolean success = Arrays.equals(newPlainText, message);
            assertTrue("Decrypted text does not match expected, msglen=" + message.length, success);

            // Verify the text again
            cp.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText2 = cp.doFinal(cipherText, 0, cipherText.length);

            success = Arrays.equals(newPlainText2, message);
            assertTrue("Decrypted text does not match expected, msglen=" + message.length, success);
        } catch (IllegalBlockSizeException e) {
            assertTrue(
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length,
                    (!requireLengthMultipleBlockSize || (message.length % blockSize) != 0));
        }
    }

    // --------------------------------------------------------------------------
    // Run encrypt/decrypt test using just update, empty doFinal calls
    //
    protected void encryptDecryptUpdate(String algorithm, boolean requireLengthMultipleBlockSize,
            AlgorithmParameters algParams, byte[] message) throws Exception {
        if (isTransformationValidButUnsupported(algorithm)) {
            return;
        }
        Cipher cp = Cipher.getInstance(algorithm, encryptProviderName);
        if (algParams == null) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cp.getBlockSize();
        try {
            byte[] cipherText1 = cp.update(message);
            byte[] cipherText2 = cp.doFinal();
            params = cp.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length,
                        ((message.length % blockSize) == 0));
            }

            // Verify the text
            if (providerName.equals(encryptProviderName) == false) {
                cp = Cipher.getInstance(algorithm, providerName);
            }
            cp.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText1 = (cipherText1 == null) ? new byte[0] : cp.update(cipherText1);
            byte[] newPlainText2 = cp.doFinal(cipherText2);

            int l = (newPlainText1 == null) ? 0 : newPlainText1.length;
            byte[] newPlainText = new byte[l + newPlainText2.length];

            if (l != 0) {
                System.arraycopy(newPlainText1, 0, newPlainText, 0, l);
            }
            System.arraycopy(newPlainText2, 0, newPlainText, l, newPlainText2.length);

            boolean success = Arrays.equals(newPlainText, message);
            assertTrue("Decrypted text does not match expected, msglen=" + message.length, success);
        } catch (IllegalBlockSizeException e) {
            assertTrue(
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length,
                    (!requireLengthMultipleBlockSize || (message.length % blockSize) != 0));
        }
    }

    // --------------------------------------------------------------------------
    // Run encrypt/decrypt test with partial update
    //
    protected void encryptDecryptPartialUpdate(String algorithm,
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message)
            throws Exception {
        if (isTransformationValidButUnsupported(algorithm)) {
            return;
        }
        Cipher cp = Cipher.getInstance(algorithm, encryptProviderName);
        if (algParams == null) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cp.getBlockSize();
        int partialLen = message.length > 10 ? 10 : 1;
        try {
            byte[] cipherText1 = cp.update(message, 0, partialLen);
            byte[] cipherText2 = cp.doFinal(message, partialLen, message.length - partialLen);
            params = cp.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length,
                        ((message.length % blockSize) == 0));
            }

            // Verify the text
            if (providerName.equals(encryptProviderName) == false) {
                cp = Cipher.getInstance(algorithm, providerName);
            }
            cp.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText1 = (cipherText1 == null) ? new byte[0] : cp.update(cipherText1);
            byte[] newPlainText2 = cp.doFinal(cipherText2);

            int l = (newPlainText1 == null) ? 0 : newPlainText1.length;
            byte[] newPlainText = new byte[l + newPlainText2.length];

            if (l != 0) {
                System.arraycopy(newPlainText1, 0, newPlainText, 0, l);
            }
            System.arraycopy(newPlainText2, 0, newPlainText, l, newPlainText2.length);

            boolean success = Arrays.equals(newPlainText, message);
            assertTrue("Decrypted text does not match expected, partial msglen=" + message.length,
                    success);
        } catch (IllegalBlockSizeException e) {
            assertTrue(
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length,
                    (!requireLengthMultipleBlockSize || (message.length % blockSize) != 0));
        }
    }

    // --------------------------------------------------------------------------
    // Run encrypt/decrypt test reusing cipher object
    //
    protected void encryptDecryptReuseObject(String algorithm,
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message)
            throws Exception

    {
        if (isTransformationValidButUnsupported(algorithm)) {
            return;
        }

        Cipher cp = Cipher.getInstance(algorithm, encryptProviderName);
        if (algParams == null) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cp.getBlockSize();
        try {
            byte[] cipherText = cp.doFinal(message);
            params = cp.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length,
                        ((blockSize > 0) && (message.length % blockSize) == 0));
            }

            // Verify that the cipher object can be used to encrypt again
            // without re-init
            byte[] cipherText2 = cp.doFinal(message);
            boolean success = Arrays.equals(cipherText2, cipherText);
            assertTrue("Re-encrypted text does not match", success);

            // Verify the text
            if (providerName.equals(encryptProviderName) == false) {
                cp = Cipher.getInstance(algorithm, providerName);
            }
            cp.init(Cipher.DECRYPT_MODE, key, params);
            byte[] newPlainText = cp.doFinal(cipherText);
            success = Arrays.equals(newPlainText, message);
            assertTrue("Decrypted text does not match expected, msglen=" + message.length, success);

            // Verify that the cipher object can be used to decrypt again
            // without re-init
            byte[] newPlainText2 = cp.doFinal(cipherText, 0, cipherText.length);
            success = Arrays.equals(newPlainText2, newPlainText);
            assertTrue("Re-decrypted text does not match", success);
        } catch (IllegalBlockSizeException e) {
            assertTrue(
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length,
                    (!requireLengthMultipleBlockSize || (message.length % blockSize) != 0));
        }
    }

    // --------------------------------------------------------------------------
    // Run encrypt/decrypt test using just doFinal calls (copy-safe)
    //
    protected void encryptDecryptDoFinalCopySafe(String algorithm,
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message)
            throws Exception

    {
        if (isTransformationValidButUnsupported(algorithm)) {
            return;
        }

        Cipher cp = Cipher.getInstance(algorithm, encryptProviderName);
        if (algParams == null) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cp.getBlockSize();
        try {
            byte[] cipherText0 = cp.doFinal(message);

            byte[] resultBuffer = Arrays.copyOf(message, cp.getOutputSize(message.length));
            int resultLen = cp.doFinal(resultBuffer, 0, message.length, resultBuffer);
            byte[] cipherText = Arrays.copyOf(resultBuffer, resultLen);
            params = cp.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length,
                        ((blockSize > 0) && (message.length % blockSize) == 0));
            }

            boolean success = Arrays.equals(cipherText, cipherText0);
            assertTrue("Encrypted text does not match expected result", success);

            // Verify the text
            if (providerName.equals(encryptProviderName) == false) {
                cp = Cipher.getInstance(algorithm, providerName);
            }
            cp.init(Cipher.DECRYPT_MODE, key, params);
            resultBuffer = Arrays.copyOf(cipherText, cp.getOutputSize(cipherText.length));
            resultLen = cp.doFinal(resultBuffer, 0, cipherText.length, resultBuffer);
            byte[] newPlainText = Arrays.copyOf(resultBuffer, resultLen);

            success = Arrays.equals(newPlainText, message);
            assertTrue("Decrypted text does not match expected, msglen=" + message.length, success);
        } catch (IllegalBlockSizeException e) {
            assertTrue(
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length,
                    (!requireLengthMultipleBlockSize || (message.length % blockSize) != 0));
        }
    }

    // --------------------------------------------------------------------------
    // Run encrypt/decrypt test using just update, empty doFinal calls
    // (copy-safe)
    //
    protected void encryptDecryptUpdateCopySafe(String algorithm,
            boolean requireLengthMultipleBlockSize, AlgorithmParameters algParams, byte[] message)
            throws Exception

    {
        if (isTransformationValidButUnsupported(algorithm)) {
            return;
        }

        Cipher cp = Cipher.getInstance(algorithm, encryptProviderName);
        if (algParams == null) {
            cp.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cp.init(Cipher.ENCRYPT_MODE, key, algParams);
        }
        int blockSize = cp.getBlockSize();
        try {
            byte[] cipherText0 = cp.doFinal(message);

            byte[] resultBuffer = Arrays.copyOf(message, cp.getOutputSize(message.length));
            int cipherText1Len = cp.update(resultBuffer, 0, message.length, resultBuffer);
            byte[] cipherText2 = cp.doFinal();

            byte[] cipherText = new byte[cipherText1Len + cipherText2.length];
            System.arraycopy(resultBuffer, 0, cipherText, 0, cipherText1Len);
            System.arraycopy(cipherText2, 0, cipherText, cipherText1Len, cipherText2.length);
            params = cp.getParameters();

            if (requireLengthMultipleBlockSize) {
                assertTrue(
                        "Did not get expected IllegalBlockSizeException, blockSize=" + blockSize
                                + ", msglen=" + message.length,
                        ((blockSize > 0) && (message.length % blockSize) == 0));
            }

            boolean success = Arrays.equals(cipherText, cipherText0);
            assertTrue("Encrypted text does not match expected result", success);

            // Verify the text
            if (providerName.equals(encryptProviderName) == false) {
                cp = Cipher.getInstance(algorithm, providerName);
            }
            cp.init(Cipher.DECRYPT_MODE, key, params);
            resultBuffer = Arrays.copyOf(cipherText, cp.getOutputSize(cipherText.length));
            int plainText1Len = cp.update(resultBuffer, 0, cipherText.length, resultBuffer);
            byte[] plainText2 = cp.doFinal();

            byte[] newPlainText = new byte[plainText1Len + plainText2.length];
            System.arraycopy(resultBuffer, 0, newPlainText, 0, plainText1Len);
            System.arraycopy(plainText2, 0, newPlainText, plainText1Len, plainText2.length);

            success = Arrays.equals(newPlainText, message);
            assertTrue("Decrypted text does not match expected, msglen=" + message.length, success);
        } catch (IllegalBlockSizeException e) {
            assertTrue(
                    "Unexpected IllegalBlockSizeException, blockSize=" + blockSize + ", msglen="
                            + message.length,
                    (!requireLengthMultipleBlockSize || (message.length % blockSize) != 0));
        }
    }
}
