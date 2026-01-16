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
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

public class BaseTestRSACipherInterop extends BaseTestJunit5Interop {
    private KeyFactory rsaKeyFactoryPlus;
    private KeyFactory rsaKeyFactorySun;

    private KeyPair rsaKeyPairPlus;
    private KeyPair rsaKeyPairSun;

    @BeforeEach
    public void setUp() throws Exception {
        KeyPairGenerator rsaKeyPairGenPlus = KeyPairGenerator.getInstance("RSA", getProviderName());
        rsaKeyPairGenPlus.initialize(getKeySize());
        rsaKeyPairPlus = rsaKeyPairGenPlus.generateKeyPair();

        KeyPairGenerator rsaKeyPairGenSun = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
        rsaKeyPairGenSun.initialize(getKeySize());
        rsaKeyPairSun = rsaKeyPairGenSun.generateKeyPair();

        rsaKeyFactoryPlus = KeyFactory.getInstance("RSA", getProviderName());
        rsaKeyFactorySun = KeyFactory.getInstance("RSA", "SunRsaSign");
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

        String alg = "RSA/ECB/" + padding;
        testEncryptDecryptInterop(alg, rsaKeyPairPlus, getProviderName(), getInteropProviderName());
        testEncryptDecryptInterop(alg, rsaKeyPairSun, getInteropProviderName(), getProviderName());
        testEncryptDecryptInterop(alg, rsaKeyPairSun, getProviderName(), getInteropProviderName());
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

        String alg = "RSA/ECB/" + padding;
        testEncryptImportDecryptInterop(alg, rsaKeyPairPlus, rsaKeyFactorySun, getProviderName(), getInteropProviderName());
        testEncryptImportDecryptInterop(alg, rsaKeyPairSun, rsaKeyFactoryPlus, getInteropProviderName(), getProviderName());
        testEncryptImportDecryptInterop(alg, rsaKeyPairSun, rsaKeyFactoryPlus, getProviderName(), getInteropProviderName());
        testEncryptImportDecryptInterop(alg, rsaKeyPairPlus, rsaKeyFactorySun, getInteropProviderName(), getProviderName());
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

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", getProviderName());
        kpg.initialize(getKeySize());
        KeyPair kp = kpg.generateKeyPair();

        byte[] msgBytes = ("This is a short msg".getBytes());
        byte[] cipherText;

        Cipher cipherEncrypt = Cipher.getInstance(alg, encryptProvider);
        cipherEncrypt.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        cipherText = cipherEncrypt.doFinal(msgBytes);

        Cipher cipherDecrypt = Cipher.getInstance(alg, decryptProvider);
        cipherDecrypt.init(Cipher.DECRYPT_MODE, kp.getPrivate());
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

        testEncryptDecryptParamsInterop(md, mgf1, rsaKeyPairPlus, getProviderName(), getInteropProviderName());
        testEncryptDecryptParamsInterop(md, mgf1, rsaKeyPairSun, getInteropProviderName(), getProviderName());
        testEncryptDecryptParamsInterop(md, mgf1, rsaKeyPairSun, getProviderName(), getInteropProviderName());
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

        testEncryptImportDecryptParamsInterop(md, mgf1, rsaKeyPairPlus, rsaKeyFactorySun, getProviderName(), getInteropProviderName());
        testEncryptImportDecryptParamsInterop(md, mgf1, rsaKeyPairSun, rsaKeyFactoryPlus, getInteropProviderName(), getProviderName());
        testEncryptImportDecryptParamsInterop(md, mgf1, rsaKeyPairSun, rsaKeyFactoryPlus, getProviderName(), getInteropProviderName());
        testEncryptImportDecryptParamsInterop(md, mgf1, rsaKeyPairPlus, rsaKeyFactorySun, getInteropProviderName(), getProviderName());
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

    /*
     * for printing binary.
     */
    String toHex(byte[] data) {
        String digits = "0123456789abcdef";
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xff;
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        return buf.toString();
    }
}
