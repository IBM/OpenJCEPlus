/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class BaseTestRSACipherInterop extends BaseTestJunit5Interop {
    private KeyFactory rsaKeyFactoryPlus;
    private KeyFactory rsaKeyFactoryInterop;

    private KeyPair rsaKeyPairPlus;
    private KeyPair rsaKeyPairInterop;

    @BeforeEach
    public void setUp() throws Exception {
        KeyPairGenerator rsaKeyPairGenPlus = KeyPairGenerator.getInstance("RSA", getProviderName());
        rsaKeyPairGenPlus.initialize(getKeySize());
        rsaKeyPairPlus = rsaKeyPairGenPlus.generateKeyPair();

        String rsaKeyProvider = "SunJCE".equals(getInteropProviderName()) ? "SunRsaSign" : getInteropProviderName();
        KeyPairGenerator rsaKeyPairGenInterop = KeyPairGenerator.getInstance("RSA", rsaKeyProvider);
        rsaKeyPairGenInterop.initialize(getKeySize());
        rsaKeyPairInterop = rsaKeyPairGenInterop.generateKeyPair();

        rsaKeyFactoryPlus = KeyFactory.getInstance("RSA", getProviderName());
        rsaKeyFactoryInterop = KeyFactory.getInstance("RSA", rsaKeyProvider);
    }

    @ParameterizedTest
    @CsvSource({"OAEPPADDING", "OAEPWITHSHA1ANDMGF1PADDING", "OAEPWITHSHA-1ANDMGF1PADDING",
                "OAEPWITHSHA-224ANDMGF1PADDING",
                "OAEPWITHSHA-256ANDMGF1PADDING",
                "OAEPWITHSHA-384ANDMGF1PADDING",
                "OAEPWITHSHA-512ANDMGF1PADDING",
                "OAEPWITHSHA-512/224ANDMGF1PADDING",
                "OAEPWITHSHA-512/256ANDMGF1PADDING",
                "NOPADDING", "PKCS1PADDING"})
    public void testEncryptDecryptInterop(String padding) throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        // OAEP from BC requires an explicit spec due to differing MGF1 defaults.
        assumeFalse("BC".equals(getInteropProviderName())
                && !padding.equals("NOPADDING") && !padding.equals("PKCS1PADDING"));

        String alg = "RSA/ECB/" + padding;
        testEncryptDecryptInterop(alg, rsaKeyPairPlus, getProviderName(), getInteropProviderName());
        testEncryptDecryptInterop(alg, rsaKeyPairInterop, getInteropProviderName(), getProviderName());
        testEncryptDecryptInterop(alg, rsaKeyPairInterop, getProviderName(), getInteropProviderName());
        testEncryptDecryptInterop(alg, rsaKeyPairPlus, getInteropProviderName(), getProviderName());
    }

    private void testEncryptDecryptInterop(String alg, KeyPair rsaKeyPair,
            String encryptProvider, String decryptProvider) throws Exception {
        RSAPublicKey rsaPublic = (RSAPublicKey) rsaKeyPair.getPublic();
        RSAPrivateCrtKey rsaPrivate = (RSAPrivateCrtKey) rsaKeyPair.getPrivate();

        testEncryptDecrypt(alg, rsaPrivate, rsaPublic, encryptProvider, decryptProvider);
    }

    @ParameterizedTest
    @CsvSource({"OAEPPADDING", "OAEPWITHSHA1ANDMGF1PADDING", "OAEPWITHSHA-1ANDMGF1PADDING",
                "OAEPWITHSHA-224ANDMGF1PADDING",
                "OAEPWITHSHA-256ANDMGF1PADDING",
                "OAEPWITHSHA-384ANDMGF1PADDING",
                "OAEPWITHSHA-512ANDMGF1PADDING",
                "OAEPWITHSHA-512/224ANDMGF1PADDING",
                "OAEPWITHSHA-512/256ANDMGF1PADDING",
                "NOPADDING", "PKCS1PADDING"})
    public void testEncryptImportDecryptInterop(String padding) throws Exception {
        // OAEP from OpenJCEPlusFIPS requires initialization with spec.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        // OAEP from BC requires an explicit spec due to differing MGF1 defaults.
        assumeFalse("BC".equals(getInteropProviderName())
                && !padding.equals("NOPADDING") && !padding.equals("PKCS1PADDING"));

        String alg = "RSA/ECB/" + padding;
        testEncryptImportDecryptInterop(alg, rsaKeyPairPlus, rsaKeyFactoryInterop, getProviderName(), getInteropProviderName());
        testEncryptImportDecryptInterop(alg, rsaKeyPairInterop, rsaKeyFactoryPlus, getInteropProviderName(), getProviderName());
        testEncryptImportDecryptInterop(alg, rsaKeyPairInterop, rsaKeyFactoryPlus, getProviderName(), getInteropProviderName());
        testEncryptImportDecryptInterop(alg, rsaKeyPairPlus, rsaKeyFactoryInterop, getInteropProviderName(), getProviderName());
    }

    private void testEncryptImportDecryptInterop(String alg, KeyPair rsaKeyPair, KeyFactory kf,
            String encryptProvider, String decryptProvider) throws Exception {
        RSAPublicKey rsaPublic = (RSAPublicKey) rsaKeyPair.getPublic();
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(
                rsaKeyPair.getPrivate().getEncoded());
        RSAPrivateCrtKey rsaPriv = (RSAPrivateCrtKey) kf.generatePrivate(pkcs8Spec);
        testEncryptDecrypt(alg, rsaPriv, rsaPublic, encryptProvider, decryptProvider);

        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(rsaKeyPair.getPublic().getEncoded());
        rsaPublic = (RSAPublicKey) kf.generatePublic(x509Spec);
        rsaPriv = (RSAPrivateCrtKey) rsaKeyPair.getPrivate();
        testEncryptDecrypt(alg, rsaPriv, rsaPublic, encryptProvider, decryptProvider);
    }

    private void testEncryptDecrypt(String alg, RSAPrivateCrtKey rsaPrivate, RSAPublicKey rsaPublic,
            String encryptProvider, String decryptProvider) throws Exception {

        byte[] msgBytes = ("This is a short msg".getBytes());
        byte[] cipherText;

        Cipher cipherEncrypt = Cipher.getInstance(alg, encryptProvider);
        cipherEncrypt.init(Cipher.ENCRYPT_MODE, rsaPublic);
        cipherText = cipherEncrypt.doFinal(msgBytes);

        Cipher cipherDecrypt = Cipher.getInstance(alg, decryptProvider);
        cipherDecrypt.init(Cipher.DECRYPT_MODE, rsaPrivate);
        byte[] decryptedBytes = stripLeadingZeroes(cipherDecrypt.doFinal(cipherText));

        assertArrayEquals(msgBytes, decryptedBytes);
    }

    @ParameterizedTest
    @CsvSource({"SHA-1, SHA-1",
                "SHA-224, SHA-224",
                "SHA-256, SHA-256",
                "SHA-384, SHA-384",
                "SHA-512, SHA-512",
                "SHA-512/224, SHA-512/224",
                "SHA-512/256, SHA-512/256",
                "SHA-224, SHA-1",
                "SHA-256, SHA-1",
                "SHA-384, SHA-1",
                "SHA-512, SHA-1",
                "SHA-512/224, SHA-1",
                "SHA-512/256, SHA-1",
                "SHA-1, SHA-224",
                "SHA-1, SHA-256",
                "SHA-1, SHA-384",
                "SHA-1, SHA-512",
                "SHA-1, SHA-512/224",
                "SHA-1, SHA-512/256",
    })
    public void testEncryptDecryptParamsInterop(String md, String mgf1) throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()) && (md.equals("SHA-1") || mgf1.equals("SHA-1")));

        // BC does not support truncated digests (SHA-512/224, SHA-512/256).
        assumeFalse("BC".equals(getInteropProviderName())
                && (md.equals("SHA-512/224") || md.equals("SHA-512/256")
                    || mgf1.equals("SHA-512/224") || mgf1.equals("SHA-512/256")));

        testEncryptDecryptParamsInterop(md, mgf1, rsaKeyPairPlus, getProviderName(), getInteropProviderName());
        testEncryptDecryptParamsInterop(md, mgf1, rsaKeyPairInterop, getInteropProviderName(), getProviderName());
        testEncryptDecryptParamsInterop(md, mgf1, rsaKeyPairInterop, getProviderName(), getInteropProviderName());
        testEncryptDecryptParamsInterop(md, mgf1, rsaKeyPairPlus, getInteropProviderName(), getProviderName());
    }

    private void testEncryptDecryptParamsInterop(String md, String mgf1, KeyPair rsaKeyPair,
            String encryptProvider, String decryptProvider) throws Exception {
        RSAPublicKey rsaPublic = (RSAPublicKey) rsaKeyPair.getPublic();
        RSAPrivateCrtKey rsaPrivate = (RSAPrivateCrtKey) rsaKeyPair.getPrivate();

        testEncryptDecryptParams(md, mgf1, rsaPrivate, rsaPublic, encryptProvider, decryptProvider);
    }

    @ParameterizedTest
    @CsvSource({"SHA-1, SHA-1",
                "SHA-224, SHA-224",
                "SHA-256, SHA-256",
                "SHA-384, SHA-384",
                "SHA-512, SHA-512",
                "SHA-512/224, SHA-512/224",
                "SHA-512/256, SHA-512/256",
                "SHA-224, SHA-1",
                "SHA-256, SHA-1",
                "SHA-384, SHA-1",
                "SHA-512, SHA-1",
                "SHA-512/224, SHA-1",
                "SHA-512/256, SHA-1",
                "SHA-1, SHA-224",
                "SHA-1, SHA-256",
                "SHA-1, SHA-384",
                "SHA-1, SHA-512",
                "SHA-1, SHA-512/224",
                "SHA-1, SHA-512/256",
    })
    public void testEncryptImportDecryptParamsInterop(String md, String mgf1) throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()) && (md.equals("SHA-1") || mgf1.equals("SHA-1")));

        // BC does not support truncated digests (SHA-512/224, SHA-512/256).
        assumeFalse("BC".equals(getInteropProviderName())
                && (md.equals("SHA-512/224") || md.equals("SHA-512/256")
                    || mgf1.equals("SHA-512/224") || mgf1.equals("SHA-512/256")));

        testEncryptImportDecryptParamsInterop(md, mgf1, rsaKeyPairPlus, rsaKeyFactoryInterop, getProviderName(), getInteropProviderName());
        testEncryptImportDecryptParamsInterop(md, mgf1, rsaKeyPairInterop, rsaKeyFactoryPlus, getInteropProviderName(), getProviderName());
        testEncryptImportDecryptParamsInterop(md, mgf1, rsaKeyPairInterop, rsaKeyFactoryPlus, getProviderName(), getInteropProviderName());
        testEncryptImportDecryptParamsInterop(md, mgf1, rsaKeyPairPlus, rsaKeyFactoryInterop, getInteropProviderName(), getProviderName());
    }

    private void testEncryptImportDecryptParamsInterop(String md, String mgf1, KeyPair rsaKeyPair, KeyFactory kf,
            String encryptProvider, String decryptProvider) throws Exception {
        RSAPublicKey rsaPublic = (RSAPublicKey) rsaKeyPair.getPublic();
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(
                rsaKeyPair.getPrivate().getEncoded());
        RSAPrivateCrtKey rsaPriv = (RSAPrivateCrtKey) kf.generatePrivate(pkcs8Spec);
        testEncryptDecryptParams(md, mgf1, rsaPriv, rsaPublic, encryptProvider, decryptProvider);

        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(rsaKeyPair.getPublic().getEncoded());
        rsaPublic = (RSAPublicKey) kf.generatePublic(x509Spec);
        rsaPriv = (RSAPrivateCrtKey) rsaKeyPair.getPrivate();
        testEncryptDecryptParams(md, mgf1, rsaPriv, rsaPublic, encryptProvider, decryptProvider);
    }

    private void testEncryptDecryptParams(String md, String mgf1, RSAPrivateCrtKey rsaPrivate, RSAPublicKey rsaPublic,
            String encryptProvider, String decryptProvider) throws Exception {

        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
            md,
            "MGF1",
            new MGF1ParameterSpec(mgf1),
            PSource.PSpecified.DEFAULT
        );

        byte[] msgBytes = ("This is a short msg".getBytes());
        byte[] cipherText;

        Cipher cipherEncrypt = Cipher.getInstance("RSA/ECB/OAEPPadding", encryptProvider);
        cipherEncrypt.init(Cipher.ENCRYPT_MODE, rsaPublic, oaepParams);
        cipherText = cipherEncrypt.doFinal(msgBytes);

        Cipher cipherDecrypt = Cipher.getInstance("RSA/ECB/OAEPPadding", decryptProvider);
        cipherDecrypt.init(Cipher.DECRYPT_MODE, rsaPrivate, oaepParams);
        byte[] decryptedBytes = stripLeadingZeroes(cipherDecrypt.doFinal(cipherText));

        assertArrayEquals(msgBytes, decryptedBytes);
    }

    @Test
    public void testEncryptDecryptBCDefaultOAEPThrows() throws Exception {
        assumeTrue("BC".equals(getInteropProviderName()));
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        testEncryptDecryptBCDefaultOAEPThrows(getProviderName(), getInteropProviderName());
        testEncryptDecryptBCDefaultOAEPThrows(getInteropProviderName(), getProviderName());
    }

    private void testEncryptDecryptBCDefaultOAEPThrows(
            String encryptProvider, String decryptProvider) throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", encryptProvider);
        kpg.initialize(getKeySize());
        KeyPair rsaKeyPair = kpg.generateKeyPair();

        RSAPublicKey rsaPublic = (RSAPublicKey) rsaKeyPair.getPublic();
        RSAPrivateCrtKey rsaPrivate = (RSAPrivateCrtKey) rsaKeyPair.getPrivate();

        Cipher cipherEncrypt = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", encryptProvider);
        cipherEncrypt.init(Cipher.ENCRYPT_MODE, rsaPublic);
        byte[] cipherText = cipherEncrypt.doFinal("This is a short msg".getBytes());

        try {
            Cipher cipherDecrypt = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", decryptProvider);
            cipherDecrypt.init(Cipher.DECRYPT_MODE, rsaPrivate);
            byte[] decrypted = cipherDecrypt.doFinal(cipherText);

            assertNotEquals("This is a short msg", new String(decrypted));
        } catch (BadPaddingException ex) {
            assertEquals("unable to decrypt block", ex.getMessage());
        }
    }

    private byte[] stripLeadingZeroes(byte[] array) {
        int i = 0;
        for (; i < array.length; i++) {
            if (array[i] != (byte) 0x00) {
                break;
            }
        }

        if (i != 0) {
            array = Arrays.copyOfRange(array, i, array.length);
        }
        return array;
    }
}
