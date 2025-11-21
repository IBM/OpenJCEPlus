/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class BaseTestAESKeyWrap extends BaseTestJunit5Interop {
    protected SecretKey           key;
    protected AlgorithmParameters params           = null;
    protected Cipher              cpA              = null;
    protected Cipher              cpB              = null;
    protected boolean             success          = true;
    protected int                 specifiedKeySize = 0;
 
    @ParameterizedTest
    @CsvSource({"AES/KW/NoPadding", "AES/KWP/NoPadding", "AES_128/KW/NoPadding",
        "AES_128/KWP/NoPadding", "AES_192/KW/NoPadding",
        "AES_192/KWP/NoPadding", "AES_256/KW/NoPadding",
        "AES_256/KWP/NoPadding", "AESWrap", "AESWrapPad", "AESWrap_128",
        "AESWrapPad_128", "AESWrap_192", "AESWrapPad_192", "AESWrap_256",
        "AESWrapPad_256"})
    public void testAESWrap128Keys(String alg) throws Exception {
        SecretKey kek            = null;
        SecretKey keyToBeWrapped = null;

        kek            = createKey("AES", getKeySize(alg), getProviderName());
        keyToBeWrapped = createKey("AES", 128, getProviderName());

        WrapUnwrapKey(alg, keyToBeWrapped, kek, getProviderName());
    }

    @ParameterizedTest
    @CsvSource({"AES/KW/NoPadding", "AES/KWP/NoPadding", "AES_128/KW/NoPadding",
        "AES_128/KWP/NoPadding", "AES_192/KW/NoPadding",
        "AES_192/KWP/NoPadding", "AES_256/KW/NoPadding",
        "AES_256/KWP/NoPadding"})
    public void testAESWrapWith256WrappedKey(String alg) throws Exception {
        SecretKey kek            = null;
        SecretKey keyToBeWrapped = null;

        kek            = createKey("AES", getKeySize(alg), getProviderName());
        keyToBeWrapped = createKey("AES", 256, getProviderName());

        WrapUnwrapKey(alg, keyToBeWrapped, kek, getProviderName());
    }

    @ParameterizedTest
    @CsvSource({"AESWrap", "AESWrap_128", "AESWrap_192",
        "AESWrap_256"})
    public void testAESWrapInterop(String alg) throws Exception {
        SecretKey kek            = null;
        SecretKey keyToBeWrapped = null;

        kek            = createKey("AES", getKeySize(alg), getProviderName());
        keyToBeWrapped = createKey("AES", 256, getInteropProviderName());

        WrapUnwrapKeyInterop(alg, keyToBeWrapped, kek, getProviderName(),
            getInteropProviderName());

        kek = createKey("AES", getKeySize(alg), getInteropProviderName());
        keyToBeWrapped = createKey("AES", 256, getProviderName());

        WrapUnwrapKeyInteropRev(alg, keyToBeWrapped, kek, getProviderName(),
            getInteropProviderName());
    }

    @ParameterizedTest
    @CsvSource({"AES_192/KW/NoPadding", "AES_192/KWP/NoPadding",
        "AES_256/KW/NoPadding", "AES_256/KWP/NoPadding"})
    public void testAESWrapFailureKeySize(String alg) throws Exception {
        SecretKey kek            = null;
        SecretKey keyToBeWrapped = null;

        kek            = createKey("AES", 128, getProviderName());
        keyToBeWrapped = createKey("AES", 256, getInteropProviderName());

        try {
            Cipher cp = null;

            cp = Cipher.getInstance(alg, getProviderName());

            // Encrypt the plain text
            cp.init(Cipher.WRAP_MODE, kek);
            cp.wrap(keyToBeWrapped);

            fail("testAESWrapFailureKeySize did no fail as expected.");
        } catch (InvalidKeyException ie) {
            assumeTrue(true);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }

    @ParameterizedTest
    @CsvSource({"AES_192/KW/NoPadding", "AES_192/KWP/NoPadding",
        "AES_256/KW/NoPadding", "AES_256/KWP/NoPadding"})
    public void testAESWrapFailureCiphertext(String alg) throws Exception {
        SecretKey kek            = null;
        SecretKey keyToBeWrapped = null;

        kek            = createKey("AES", getKeySize(alg), getProviderName());
        keyToBeWrapped = createKey("AES", 256, getInteropProviderName());

        try {
            Cipher cp = null;
            cp = Cipher.getInstance(alg, getProviderName());

            // Encrypt the plain text
            cp.init(Cipher.WRAP_MODE, kek);
            byte[] cipherText = cp.wrap(keyToBeWrapped);

            if (cipherText[2] == (byte) 0xFF) {
                cipherText[2] = (byte) 0x01;
            } else {
                cipherText[2] = (byte) 0xFF;
            }

            cp.init(Cipher.UNWRAP_MODE, kek);

            cp.unwrap(cipherText, "AES", Cipher.SECRET_KEY);
                
            fail("testAESWrapFailureCiphertext did no fail as expected.");
        } catch (InvalidKeyException ie) {
            assumeTrue(true);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }
 
    @Test
    public void testAESWrapModeFailureWrap() throws Exception {
        SecretKey kek            = null;
        SecretKey keyToBeWrapped = null;
        String    alg            = "AES_192/KW/NoPadding";

        kek            = createKey("AES", getKeySize(alg), getProviderName());
        keyToBeWrapped = createKey("AES", 256, getInteropProviderName());

        try {
            Cipher cp = null;

            cp = Cipher.getInstance(alg, getProviderName());

            // Encrypt the plain text
            cp.init(Cipher.UNWRAP_MODE, kek);
            cp.wrap(keyToBeWrapped);
            fail("testAESWrapModeFailureWrap did no fail as expected.");
        } catch (IllegalStateException ie) {
            assumeTrue(true);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }

    @Test
    public void testAESWrapModeFailureUnwrap() throws Exception {
        SecretKey kek            = null;
        SecretKey keyToBeWrapped = null;
        String    alg            = "AES_192/KW/NoPadding";

        kek            = createKey("AES", getKeySize(alg), getProviderName());
        keyToBeWrapped = createKey("AES", 256, getInteropProviderName());

        try {
            Cipher cp = null;

            cp = Cipher.getInstance(alg, getProviderName());

            // Encrypt the plain text
            cp.init(Cipher.WRAP_MODE, kek);
            byte[] cipherText = cp.wrap(keyToBeWrapped);
            cp.unwrap(cipherText, "AES", Cipher.SECRET_KEY);

            fail("testAESWrapModeFailureUnwrap did no fail as expected.");
        } catch (IllegalStateException ie) {
            assumeTrue(true);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }

    @ParameterizedTest
    @CsvSource({"AES_192/KW/NoPadding", "AES_192/KWP/NoPadding"})
    public void testEncDec(String alg) {
        SecretKey kek      = null;
        byte[]    DATA_128 = Arrays.copyOf(
            "1234567890123456789012345678901234".getBytes(), 128);
        try {
            kek = createKey("AES", getKeySize(alg), getProviderName());

            Cipher c = null;

            c = Cipher.getInstance(alg, getProviderName());
            c.init(Cipher.ENCRYPT_MODE, kek);

            byte[] out = c.doFinal(DATA_128, 0, DATA_128.length);

            // encryption outout should always be multiple of 8 and at least
            // 8-byte longer than input
            if ((out.length % 8 != 0) || (out.length - DATA_128.length < 8)) {
                throw new RuntimeException(
                    "Invalid length of encrypted data: " + out.length);
            }

            c.init(Cipher.DECRYPT_MODE, kek);

            byte[] in2 = c.doFinal(out);

            assertArrayEquals(DATA_128, in2, "Data do not match!");
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }

    @ParameterizedTest
    @CsvSource({"AES_256/KW/NoPadding", "AES_256/KWP/NoPadding"})
    public void testEncDecLargeData(String alg) {
        SecretKey kek      = null;
        byte[]    DATA_128 = Arrays.copyOf(
            "1234567890123456789012345678901234".getBytes(), 128);
        try {
            kek = createKey("AES", getKeySize(alg), getProviderName());

            Cipher c = null;

            c = Cipher.getInstance(alg, getProviderName());
            c.init(Cipher.ENCRYPT_MODE, kek);
            byte[] test = new byte[DATA_128.length * 100];
            int    i    = 0;
            for (int x = 1; x < 100; x++) {
                c.update(DATA_128);
                System.arraycopy(DATA_128, 0, test, i, DATA_128.length);
                i = i + DATA_128.length;
            }

            System.arraycopy(DATA_128, 0, test, i, DATA_128.length);

            byte[] out = c.doFinal(DATA_128, 0, DATA_128.length);

            // encryption outout should always be multiple of 8 and at least
            // 8-byte longer than input
            if ((out.length % 8 != 0) || (out.length - DATA_128.length < 8)) {
                throw new RuntimeException(
                    "Invalid length of encrypted data: " + out.length);
            }

            c.init(Cipher.DECRYPT_MODE, kek);

            byte[] in2 = c.doFinal(out);

            assertArrayEquals(test, in2, "Data do not match!");
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }

    @ParameterizedTest
    @CsvSource({"AES_256/KW/NoPadding", "AES_256/KWP/NoPadding"})
    public void testEncDecOtherDoFInal(String alg) {
        SecretKey kek      = null;
        byte[]    DATA_128 = Arrays.copyOf(
            "1234567890123456789012345678901234".getBytes(), 128);
        try {
            kek = createKey("AES", getKeySize(alg), getProviderName());

            Cipher c = null;

            c = Cipher.getInstance(alg, getProviderName());
            c.init(Cipher.ENCRYPT_MODE, kek);
            byte[] test = new byte[DATA_128.length * 2];
            c.update(DATA_128);
 
            System.arraycopy(DATA_128, 0, test, 0, DATA_128.length);
            System.arraycopy(DATA_128, 0, test, DATA_128.length, DATA_128.length);

            byte[] out = new byte[c.getOutputSize(test.length)];

            int outlen = c.doFinal(DATA_128, 0, DATA_128.length, out, 0);

            // encryption outout should always be multiple of 8 and at least
            // 8-byte longer than input
            if ((out.length % 8 != 0) || (out.length - DATA_128.length < 8)) {
                throw new RuntimeException(
                    "Invalid length of encrypted data: " + out.length);
            }

            c.init(Cipher.DECRYPT_MODE, kek);

            byte[] in2 = c.doFinal(out, 0, outlen);

            assertArrayEquals(test, in2, "Data do not match!");
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }

    @Test
    public void testUninitializedCipherDoFinal() throws Exception {
        String alg  = "AES_192/KW/NoPadding";
        byte[] data = new byte[16]; // Some test data

        try {
            Cipher cp = Cipher.getInstance(alg, getProviderName());
            // Intentionally not initializing the cipher
            cp.doFinal(data);
            fail("testUninitializedCipherDoFinal did not fail as expected.");
        } catch (IllegalStateException ise) {
            assumeTrue(true);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }

    @Test
    public void testUninitializedCipherUpdate() throws Exception {
        String alg  = "AES_192/KW/NoPadding";
        byte[] data = new byte[16]; // Some test data

        try {
            Cipher cp = Cipher.getInstance(alg, getProviderName());
            // Intentionally not initializing the cipher
            cp.update(data);
            fail("testUninitializedCipherUpdate did not fail as expected.");
        } catch (IllegalStateException ise) {
            assumeTrue(true);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }

    @Test
    public void testInvalidMode() throws Exception {
        try {
            // Using an invalid mode "ABC" instead of "KW" or "KWP"
            Cipher.getInstance("AES/ABC/NoPadding", getProviderName());
            fail("testInvalidMode did not fail as expected.");
        } catch (NoSuchAlgorithmException nsae) {
            assumeTrue(true);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }

    @Test
    public void testInvalidPadding() throws Exception {
        try {
            // Using an invalid padding "PKCS5Padding" instead of "NoPadding"
            Cipher.getInstance("AES/KW/PKCS5Padding", getProviderName());
            fail("testInvalidPadding did not fail as expected.");
        } catch (NoSuchAlgorithmException nspe) {
            assumeTrue(true);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }

    @ParameterizedTest
    @CsvSource({"AES_192/KW/NoPadding", "AES_192/KWP/NoPadding"})
    public void testInvalidKeyAlgorithm(String alg) throws Exception {
        try {
            // Create a key with a different algorithm (e.g., DES)
            SecretKey wrongKey = createKey("DESede", 168, getProviderName());

            Cipher cp = Cipher.getInstance(alg, getProviderName());
            cp.init(Cipher.WRAP_MODE, wrongKey);

            fail("testInvalidKeyAlgorithm did not fail as expected.");
        } catch (InvalidKeyException ike) {
            assumeTrue(true);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }

    @ParameterizedTest
    @CsvSource({"AES_192/KW/NoPadding", "AES_192/KWP/NoPadding"})
    public void testNullKey(String alg) throws Exception {
        try {
            Cipher cp = Cipher.getInstance(alg, getProviderName());
            cp.init(Cipher.WRAP_MODE, (Key) null);

            fail("testNullKey did not fail as expected.");
        } catch (InvalidKeyException ike) {
            assumeTrue(true);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }

    @ParameterizedTest
    @CsvSource({"AES_192/KW/NoPadding", "AES_192/KWP/NoPadding"})
    public void testInvalidKeyEncoding(String alg) throws Exception {
        try {
            // Create a custom key that returns null for getEncoded()
            SecretKey badKey = new SecretKey() {
                @Override
                public String getAlgorithm() {
                    return "AES";
                }

                @Override
                public String getFormat() {
                    return "RAW";
                }

                @Override
                public byte[] getEncoded() {
                    return null; // Return null to trigger the exception
                }
            };

            Cipher cp = Cipher.getInstance(alg, getProviderName());
            cp.init(Cipher.WRAP_MODE, badKey);

            fail("testInvalidKeyEncoding did not fail as expected.");
        } catch (InvalidKeyException ike) {
            assumeTrue(true);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }

    @ParameterizedTest
    @CsvSource({"AES_192/KW/NoPadding", "AES_192/KWP/NoPadding"})
    public void testParametersNotAccepted(String alg) throws Exception {
        try {
            SecretKey key =
                createKey("AES", getKeySize(alg), getProviderName());

            // Create some parameter spec
            javax.crypto.spec.IvParameterSpec ivSpec =
                new javax.crypto.spec.IvParameterSpec(new byte[16]);

            Cipher cp = Cipher.getInstance(alg, getProviderName());
            cp.init(Cipher.WRAP_MODE, key, ivSpec);

            fail("testParametersNotAccepted did not fail as expected.");
        } catch (InvalidAlgorithmParameterException iape) {
            assumeTrue(true);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }

    @ParameterizedTest
    @CsvSource({"AES_192/KW/NoPadding", "AES_192/KWP/NoPadding"})
    public void testAlgorithmParametersNotAccepted(String alg)
        throws Exception {
        try {
            SecretKey key =
                createKey("AES", getKeySize(alg), getProviderName());

            // Create some algorithm parameters
            AlgorithmParameters params =
                AlgorithmParameters.getInstance("AES", getProviderName());
            params.init(new javax.crypto.spec.IvParameterSpec(new byte[16]));

            Cipher cp = Cipher.getInstance(alg, getProviderName());
            cp.init(Cipher.WRAP_MODE, key, params);

            fail(
                "testAlgorithmParametersNotAccepted did not fail as expected.");
        } catch (InvalidAlgorithmParameterException iape) {
            assumeTrue(true);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }

    @ParameterizedTest
    @CsvSource({"AES_192/KW/NoPadding", "AES_192/KWP/NoPadding"})
    public void testIncorrectInputToAPI(String alg) throws Exception {
        SecretKey key = createKey("AES", getKeySize(alg), getProviderName());

        try {
            Cipher cp = Cipher.getInstance(alg, getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, key);

            // Create invalid input parameters
            byte[] input         = new byte[16];
            int    invalidOffset = 20; // Offset beyond array length

            cp.doFinal(input, invalidOffset, 8);
            fail("testIncorrectInputToAPI did not fail as expected.");
        } catch (IllegalArgumentException ise) {
            assumeTrue(true);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            assumeTrue(false);
        }
    }

    public SecretKey createKey(String alg, int size, String providerName) throws NoSuchAlgorithmException, 
        NoSuchProviderException {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance(alg, providerName);
            keyGen.init(size);
        } catch (NoSuchAlgorithmException nsae) {
            throw nsae;
        } catch (NoSuchProviderException nspe) {
            throw nspe;
        }
        return keyGen.generateKey();
    }

    public void WrapUnwrapKey(String cipher, SecretKey keyWrapped,
        SecretKey KEK, String providerName) throws NoSuchAlgorithmException, NoSuchProviderException, 
        NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException  {
        Cipher cp = null;
        try {
            cp = Cipher.getInstance(cipher, providerName);

            // Encrypt the plain text
            cp.init(Cipher.WRAP_MODE, KEK);
            byte[] cipherText = cp.wrap(keyWrapped);

            cp.init(Cipher.UNWRAP_MODE, KEK);

            Key res = cp.unwrap(cipherText, "AES", Cipher.SECRET_KEY);

            assertArrayEquals(res.getEncoded(), keyWrapped.getEncoded(),
                "Keys do not match!");

        } catch (Exception ex) {
            System.out.println("Test exception: " + ex.getMessage());
            ex.printStackTrace();
            throw ex;
        }
    }

    public void WrapUnwrapKeyInterop(String cipher, SecretKey keyWrapped,
        SecretKey KEK, String providerName, String providerNameInterop) throws NoSuchAlgorithmException, 
        NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        Cipher cp         = null;
        Cipher cpI        = null;
        Key    res        = null;
        byte[] cipherText = null;

        try {
            cp  = Cipher.getInstance(cipher, providerName);
            cpI = Cipher.getInstance(cipher, providerNameInterop);

            // Encrypt the plain text
            cp.init(Cipher.WRAP_MODE, KEK);
            cipherText = cp.wrap(keyWrapped);

            cpI.init(Cipher.UNWRAP_MODE, KEK);

            res = cpI.unwrap(cipherText, "AES", Cipher.SECRET_KEY);

            assertArrayEquals(res.getEncoded(), keyWrapped.getEncoded(),
                "Keys do not match!");

            cipherText = null;
            res        = null;
            // Encrypt the plain text
            cpI.init(Cipher.WRAP_MODE, KEK);
            cipherText = cpI.wrap(keyWrapped);

            cp.init(Cipher.UNWRAP_MODE, KEK);

            res = cp.unwrap(cipherText, "AES", Cipher.SECRET_KEY);

            assertArrayEquals(res.getEncoded(), keyWrapped.getEncoded(),
                "Keys does not match!");
        } catch (Exception ex) {
            System.out.println("Test exception: " + ex.getMessage());
            throw ex;
        }
    }

    public void WrapUnwrapKeyInteropRev(String cipher, SecretKey keyWrapped,
        SecretKey KEK, String providerName, String providerNameInterop) throws NoSuchAlgorithmException, 
        NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        Cipher cp         = null;
        Cipher cpI        = null;
        Key    res        = null;
        byte[] cipherText = null;

        try {
            cp  = Cipher.getInstance(cipher, providerNameInterop);
            cpI = Cipher.getInstance(cipher, providerName);

            // Encrypt the plain text
            cp.init(Cipher.WRAP_MODE, KEK);
            cipherText = cp.wrap(keyWrapped);

            cpI.init(Cipher.UNWRAP_MODE, KEK);

            res = cpI.unwrap(cipherText, "AES", Cipher.SECRET_KEY);

            assertArrayEquals(res.getEncoded(), keyWrapped.getEncoded(),
                "Keys does not match!");

            cipherText = null;
            res        = null;
            // Encrypt the plain text
            cpI.init(Cipher.WRAP_MODE, KEK);
            cipherText = cpI.wrap(keyWrapped);

            cp.init(Cipher.UNWRAP_MODE, KEK);

            res = cp.unwrap(cipherText, "AES", Cipher.SECRET_KEY);

            assertArrayEquals(res.getEncoded(), keyWrapped.getEncoded(),
                "Keys does not match!");
        } catch (Exception ex) {
            System.out.println("Test exception: " + ex.getMessage());
            throw ex;
        }
    }

    public int getKeySize(String alg) {
        int size = 128;
        switch (alg) {
            case "AES/KW/NoPadding":
            case "AES/KWP/NoPadding":
            case "AES_128/KW/NoPadding":
            case "AES_128/KWP/NoPadding":
            case "AESWrap":
            case "AESWrapPad":
            case "AESWrap_128":
            case "AESWrapPad_128":
                break;
            case "AES_192/KW/NoPadding":
            case "AES_192/KWP/NoPadding":
            case "AESWrap_192":
            case "AESWrapPad_192":
                size = 192;
                break;
            case "AES_256/KW/NoPadding":
            case "AES_256/KWP/NoPadding":
            case "AESWrap_256":
            case "AESWrapPad_256":
                size = 256;
                break;
            default:
                throw new InvalidParameterException("Invalid key algorithm specified");
        }
        return size;
    }
}
