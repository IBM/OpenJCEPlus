/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.junit.Assume;

public class BaseTestRSA extends BaseTestCipher {
    //--------------------------------------------------------------------------
    //
    //
    static final char[] hexDigits = "0123456789abcdef".toCharArray();

    static final byte[] plainText = "testmessage_a very long test message".getBytes();

    static final int DEFAULT_KEY_SIZE = 2048;

    //--------------------------------------------------------------------------
    //
    //
    protected KeyPairGenerator rsaKeyPairGen;
    protected KeyPair rsaKeyPair;
    protected RSAPublicKey rsaPub;
    protected RSAPrivateCrtKey rsaPriv;
    protected int specifiedKeySize = 0;
    protected boolean providerStripsLeadingZerosForNoPaddingDecrypt = false; // FIXME - IBMJCE tests will need this to be true

    //--------------------------------------------------------------------------
    //
    //
    public BaseTestRSA(String providerName) {
        super(providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public BaseTestRSA(String providerName, int keySize) throws Exception {
        super(providerName);
        this.specifiedKeySize = keySize;

        Assume.assumeTrue(javax.crypto.Cipher.getMaxAllowedKeyLength("RSA") >= keySize);
    }

    //--------------------------------------------------------------------------
    //
    //
    protected void setUp() throws Exception {
        rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", providerName);
        if (specifiedKeySize > 0) {
            rsaKeyPairGen.initialize(specifiedKeySize, null);
        }
        rsaKeyPair = rsaKeyPairGen.generateKeyPair();
        rsaPub = (RSAPublicKey) rsaKeyPair.getPublic();
        rsaPriv = (RSAPrivateCrtKey) rsaKeyPair.getPrivate();
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher() throws Exception {
        encryptDecrypt("RSA");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSAPlainCipher() throws Exception {
        KeyFactory kf;

        BigInteger N = new BigInteger(
                "116231208661367609700141079576488663663527180869991078124978203037949869"
                        + "312762870627991319537001781149083155962615105864954367253799351549459177"
                        + "839995715202060014346744789001273681801687605044315560723525700773069112"
                        + "214443196787519930666193675297582113726306864236010438506452172563580739"
                        + "994193451997175316921");

        BigInteger E = BigInteger.valueOf(65537);

        BigInteger D = new BigInteger(
                "528278531576995741358027120152717979850387435582102361125581844437708890"
                        + "736418759997555187916546691958396015481089485084669078137376029510618510"
                        + "203389286674134146181629472813419906337170366867244770096128371742241254"
                        + "843638089774095747779777512895029847721754360216404183209801002443859648"
                        + "26168432372077852785");

        String in2 = "0f:7d:6c:20:75:99:a5:bc:c1:53:b0:4e:8d:ef:98:fb:cf:2d:e5:1d:d4:bf:71:56:12:b7:a3:c3:e4:53:1b:07:d3:bb:94:a7:a7:28:75:1e:83:46:c9:80:4e:3f:ac:b2:47:06:9f:1b:68:38:73:b8:69:9e:6b:8b:8b:23:60:31:ae:ea:36:24:6f:85:af:de:a5:2a:88:7d:6a:9f:8a:9f:61:f6:59:3f:a8:ce:91:75:49:e9:34:b8:9f:b6:21:8c";
        String out2 = "7d:84:d1:3a:dc:ac:46:09:3a:0c:e5:4b:85:5d:fa:bb:52:f1:0f:de:d9:87:ef:b3:f7:c8:e3:9a:29:be:e9:b5:51:57:fd:07:5b:3c:1c:1c:56:aa:0c:a6:3f:79:40:16:ee:2c:2c:2e:fe:b8:3e:fd:45:90:1c:e7:87:1d:0a:0a:c5:de:9d:2b:a9:dd:77:d2:89:ba:98:fe:78:5b:a3:91:b4:ac:b5:ae:ce:45:21:f7:74:97:3e:a9:58:59:bc:14:13:02:3f:09:7b:97:90:b3:bd:53:cb:15:c0:6e:36:ea:d4:a3:3e:fc:94:85:a9:66:7f:57:b4:2a:ae:70:2e:fb";

        String in1 = "17:a3:a7:b1:86:29:06:c5:81:33:cd:2f:da:32:7c:0e:26:a8:18:aa:37:9b:dd:4a:b0:b0:a7:1c:14:82:6c:d9:c9:14:9f:55:19:91:02:0d:d9:d7:95:c2:2b:a6:fa:ba:a3:51:00:83:6b:ec:97:27:40:a3:8f:ba:b1:09:15:11:44:33:c6:3c:47:95:50:71:50:5a:f4:aa:00:4e:b9:48:6a:b1:34:e9:d0:c8:b8:92:bf:95:f3:3d:91:66:93:2b";
        String out1 = "28:b7:b4:73:f2:16:11:c0:67:70:96:ee:dc:3e:23:87:9f:30:a7:e5:f0:db:aa:67:33:27:0e:75:79:af:29:f5:88:3d:93:22:14:d2:59:b4:eb:ce:95:7f:24:74:df:f2:aa:4d:e6:65:5a:63:6d:64:30:ef:31:f1:a6:df:17:42:b6:d1:ed:22:1f:b0:96:69:9d:f8:ce:ff:3a:47:96:51:ba:d9:8d:57:39:40:dc:fc:d3:03:92:39:f4:dd:4b:1b:07:8b:33:60:27:2d:5f:c6:cf:17:92:c6:12:69:a3:54:2e:b8:0f:ca:d9:46:0f:da:95:34:d0:84:35:9c:f6:44";

        String rin1 = "09:01:06:53:a7:96:09:63:ef:e1:3f:e9:8d:95:22:d1:0e:1b:87:c1:a2:41:b2:09:97:a3:5e:e0:a4:1d:59:91:21:e4:ca:87:bf:77:4a:7e:a2:22:ff:59:1e:bd:a4:80:aa:93:4a:41:56:95:5b:f4:57:df:fc:52:2f:46:9b:45:d7:03:ae:22:8e:67:9e:6c:b9:95:4f:bd:8e:e8:67:90:5b:fe:de:2f:11:22:2e:9d:30:93:6d:c0:48:00:cb:08:b9:c4:36:e9:03:7c:08:2d:68:42:cb:71:d0:7d:47:22:c1:58:c5:b8:2f:28:3e:98:78:11:6d:71:5b:3b:36:3c";
        String rout1 = "4a:21:64:20:56:5f:27:0c:90:1d:f3:1b:64:8e:16:d3:af:79:ca:c6:65:56:19:77:8f:25:35:70:be:f3:15:b3:e3:d8:8f:04:ec:c3:60:59:d0:9a:66:be:1c:ad:f7:09:46:a9:09:46:12:5f:28:b6:28:b1:53:fb:fe:07:73:b8:8b:f8:83:64:8e:2d:45:ca:1a:fd:85:4a:2c:fa:fc:e6:58:f7:e4:83:68:8c:38:49:2b:f3:5c:c1:2d:24:6a:cd:22:6d:cb:f4:f1:8c:9e:1a:94:a7:4b:6f:d1:b4:b4:ab:56:8b:a3:a9:89:88:c3:5d:a8:47:2a:67:50:32:71:19";

        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS does not support plain keys
            return;
        }

        try {
            kf = KeyFactory.getInstance("RSA", providerName);
        } catch (NoSuchAlgorithmException e) {
            kf = KeyFactory.getInstance("RSA");
        }

        RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(N, E);
        PublicKey publicKey = kf.generatePublic(pubSpec);

        RSAPrivateKeySpec privSpec = new RSAPrivateKeySpec(N, D);
        PrivateKey privateKey = kf.generatePrivate(privSpec);

        try {
            // blocktype 2
            plainKeyEncDec("RSA/ECB/PKCS1Padding", 96, publicKey, privateKey);
            // blocktype 1
            plainKeyEncDec("RSA/ECB/NoPadding", 128, publicKey, privateKey);

            // expected failure, blocktype 2 random padding bytes are different
            plainKeyCipher("RSA/ECB/PKCS1Padding", Cipher.ENCRYPT_MODE, publicKey, in2, out2,
                    false);
            plainKeyCipher("RSA/ECB/PKCS1Padding", Cipher.DECRYPT_MODE, privateKey, out2, in2,
                    true);

            plainKeyCipher("RSA/ECB/NoPadding", Cipher.ENCRYPT_MODE, publicKey, rin1, rout1, true);
            plainKeyCipher("RSA/ECB/NoPadding", Cipher.DECRYPT_MODE, privateKey, rout1, rin1, true);
        } catch (Exception e) {
            fail("Got Exception in testRSAPlainCipher");
            return;
        }
        try {
            // decrypt something not PKCS#1 formatted
            plainKeyCipher("RSA/ECB/PKCS1Padding", Cipher.DECRYPT_MODE, privateKey, rout1, rin1,
                    true);
            fail("Should not have worked - testRSAPlainCipher");
            return;
        } catch (Exception e) {
            // ok
        }

        try {
            // decrypt with wrong key
            plainKeyCipher("RSA/ECB/PKCS1Padding", Cipher.DECRYPT_MODE, privateKey, out1, in1,
                    true);
            fail("Should not have worked - testRSAPlainCipher");
            return;
        } catch (Exception e) {
            // ok
        }

        assertTrue(true);

    }

    private void plainKeyEncDec(String alg, int len, Key encKey, Key decKey) throws Exception {
        Cipher c = Cipher.getInstance(alg, providerName);

        byte[] b = new byte[len];
        Random rnd = new Random();
        rnd.nextBytes(b);
        b[0] &= 0x3f;
        b[0] |= 1;

        c.init(Cipher.ENCRYPT_MODE, encKey);
        byte[] enc = c.doFinal(b);

        c.init(Cipher.DECRYPT_MODE, decKey);
        byte[] dec = c.doFinal(enc);

        if (Arrays.equals(b, dec) == false) {
            throw new Exception("Failure");
        }
    }

    public void plainKeyCipher(String alg, int mode, Key key, String in, String out, boolean result)
            throws Exception {
        Cipher c = Cipher.getInstance(alg, providerName);
        c.init(mode, key);
        byte[] r = c.doFinal(parse(in));
        byte[] s = parse(out);
        if (Arrays.equals(r, s) != result) {
            throw new Exception("Unexpected test result");
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_PKCS1Padding() throws Exception {
        encryptDecrypt("RSA/ECB/PKCS1Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_NoPadding() throws Exception {
        encryptDecrypt("RSA/ECB/NoPadding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_ECB_PKCS1Padding() throws Exception {
        encryptDecrypt("RSA/ECB/PKCS1Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_ECB_NoPadding() throws Exception {
        encryptDecrypt("RSA/ECB/NoPadding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_ECB_ZeroPadding() throws Exception {
        encryptDecrypt("RSA/ECB/ZeroPadding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherWithNoPad() throws Exception {
        encryptDecrypt("RSAwithNoPad");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherForSSL() throws Exception {
        encryptDecrypt("RSAforSSL");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_SSL_PKCS1Padding() throws Exception {
        encryptDecrypt("RSA/SSL/PKCS1Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherWithOAEPPadding() throws Exception {
        byte[] message = getMessage_OAEP_SHA1();
        if (message != null) {
            encryptDecrypt("RSA/ECB/OAEPPadding", message);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherWithPaddingSHA_1() throws Exception {
        byte[] message = getMessage_OAEP_SHA1();
        if (message != null) {
            encryptDecrypt("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", message);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherWithPaddingSHA1() throws Exception {
        byte[] message = getMessage_OAEP_SHA1();
        if (message != null) {
            encryptDecrypt("RSA/ECB/OAEPWithSHA1AndMGF1Padding", message);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherWithPaddingSHA224() throws Exception {
        byte[] message = getMessage_OAEP_SHA224();
        if (message != null) {
            encryptDecrypt("RSA/ECB/OAEPWithSHA-224AndMGF1Padding", message);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherWithPaddingSHA256() throws Exception {
        byte[] message = getMessage_OAEP_SHA256();
        if (message != null) {
            encryptDecrypt("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", message);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherWithPaddingSHA384() throws Exception {
        byte[] message = getMessage_OAEP_SHA384();
        if (message != null) {
            encryptDecrypt("RSA/ECB/OAEPWithSHA-384AndMGF1Padding", message);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherWithPaddingSHA512() throws Exception {
        byte[] message = getMessage_OAEP_SHA512();
        if (message != null) {
            encryptDecrypt("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSAShortBuffer() throws Exception {

        try {
            Cipher cp = Cipher.getInstance("RSA", providerName);

            // Encrypt the plain text
            cp.init(Cipher.ENCRYPT_MODE, rsaPub);
            byte[] cipherText = new byte[5];

            cp.doFinal(plainText, 0, plainText.length, cipherText);

            fail("Expected ShortBufferException did not occur");

        } catch (ShortBufferException ex) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSAShortBuffer2() throws Exception {
        String algorithm = "RSA/ECB/NoPadding";
        int outputByteLength = 64;
        int finalOffset = 65;

        try {

            Cipher cipher = Cipher.getInstance(algorithm, providerName);

            if (cipher.equals(null))
                System.out.println("The cipher was null.");

            cipher.init(Cipher.ENCRYPT_MODE, rsaPub);

            byte[] newplainText2 = new byte[outputByteLength];

            cipher.doFinal(newplainText2, finalOffset);

            fail("Expected ShortBufferException did not occur");

        } catch (ShortBufferException ex) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSABadPadding() throws Exception {

        try {
            // Test RSA Cipher
            Cipher cp = Cipher.getInstance("RSA", providerName);

            // Encrypt the plain text
            cp.init(Cipher.ENCRYPT_MODE, rsaPub);
            byte[] cipherText = cp.doFinal(plainText);

            // Verify the text
            cp.init(Cipher.DECRYPT_MODE, rsaPriv);
            cp.doFinal(cipherText, 0, cipherText.length - 1);

            fail("Expected BadPaddingException did not occur");

        } catch (BadPaddingException ex) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSAIllegalMode() throws Exception {

        // Test RSA Cipher
        Cipher cp = Cipher.getInstance("RSA/ECB/PKCS1Padding", providerName);

        // Encrypt the plain text
        cp.init(Cipher.ENCRYPT_MODE, rsaPub);
        cp.update(plainText);
        byte[] cipherText = cp.doFinal();

        // Verify the text
        cp.init(Cipher.DECRYPT_MODE, rsaPriv);
        cp.update(cipherText);
        byte[] newPlainText = cp.doFinal();

        boolean success = decryptResultsMatch(cp.getAlgorithm(), plainText, newPlainText);
        assertTrue("Decrypted text does not match expected", success);

    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_getParams() throws Exception {
        checkGetParamsNull("RSA");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_PKCS1Padding_getParams() throws Exception {
        checkGetParamsNull("RSA/ECB/PKCS1Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_NoPadding_getParams() throws Exception {
        checkGetParamsNull("RSA/ECB/NoPadding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_ECB_PKCS1Padding_getParams() throws Exception {
        checkGetParamsNull("RSA/ECB/PKCS1Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_ECB_NoPadding_getParams() throws Exception {
        checkGetParamsNull("RSA/ECB/NoPadding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_ECB_ZeroPadding_getParams() throws Exception {
        checkGetParamsNull("RSA/ECB/ZeroPadding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherWithNoPad_getParams() throws Exception {
        checkGetParamsNull("RSAwithNoPad");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherForSSL_getParams() throws Exception {
        checkGetParamsNull("RSAforSSL");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_SSL_PKCS1Padding_getParams() throws Exception {
        checkGetParamsNull("RSA/SSL/PKCS1Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherWithOAEPPadding_getParams() throws Exception {
        checkGetParamsNotNull("RSA/ECB/OAEPPadding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherWithPaddingSHA_1_getParams() throws Exception {
        checkGetParamsNotNull("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherWithPaddingSHA1_getParams() throws Exception {
        checkGetParamsNotNull("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherWithPaddingSHA224_getParams() throws Exception {
        checkGetParamsNotNull("RSA/ECB/OAEPWithSHA-224AndMGF1Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherWithPaddingSHA256_getParams() throws Exception {
        checkGetParamsNotNull("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherWithPaddingSHA384_getParams() throws Exception {
        checkGetParamsNotNull("RSA/ECB/OAEPWithSHA-384AndMGF1Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherWithPaddingSHA512_getParams() throws Exception {
        checkGetParamsNotNull("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
    }

    //--------------------------------------------------------------------------
    //
    //
    public void checkGetParamsNull(String transformation) throws Exception {
        if (isTransformationValidButUnsupported(transformation)) {
            return;
        }

        Cipher cp = Cipher.getInstance(transformation, providerName);
        cp.init(Cipher.ENCRYPT_MODE, rsaPub);
        AlgorithmParameters algParams = cp.getParameters();
        assertTrue("AlgorithmParameters not null", (algParams == null));
    }

    //--------------------------------------------------------------------------
    //
    //
    public void checkGetParamsNotNull(String transformation) throws Exception {
        if (isTransformationValidButUnsupported(transformation)) {
            return;
        }

        Cipher cp = Cipher.getInstance(transformation, providerName);
        cp.init(Cipher.ENCRYPT_MODE, rsaPub);
        AlgorithmParameters algParams = cp.getParameters();
        assertTrue("AlgorithmParameters is null", (algParams != null));
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherOutputSize() throws Exception {
        Cipher cp = Cipher.getInstance("RSA", providerName);
        cp.init(Cipher.ENCRYPT_MODE, rsaPub);
        int outputSize = cp.getOutputSize(1);

        int keySize = specifiedKeySize;
        if (keySize == 0) {
            keySize = ((java.security.interfaces.RSAKey) rsaPub).getModulus().bitLength();
        }
        assertTrue("Unexpected getOutputSize result", (outputSize == keySize / 8));
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipherExceedInput() throws Exception {
        try {
            Cipher cp = Cipher.getInstance("RSA", providerName);
            cp.init(Cipher.ENCRYPT_MODE, rsaPub);

            int n = ((RSAKey) rsaPub).getModulus().bitLength();
            int byteLength = (n + 7) >> 3;

            byte[] message = new byte[byteLength + 1];
            cp.update(message);
            cp.doFinal();

            fail("Did not get IllegalBlockSizeException");
        } catch (IllegalBlockSizeException e) {
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_cert() throws Exception {
        // FIXME
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_certnull() throws Exception {
        try {
            Cipher cp = Cipher.getInstance("RSA", providerName);
            cp.init(Cipher.ENCRYPT_MODE, (Certificate) null);
            fail("Did not get InvalidKeyException");
        } catch (InvalidKeyException e) {
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_cert_sr() throws Exception {
        // FIXME
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_certnull_sr() throws Exception {
        try {
            Cipher cp = Cipher.getInstance("RSA", providerName);
            cp.init(Cipher.ENCRYPT_MODE, (Certificate) null, new SecureRandom());
            fail("Did not get InvalidKeyException");
        } catch (InvalidKeyException e) {
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_key() throws Exception {
        Cipher cp = Cipher.getInstance("RSA", providerName);
        cp.init(Cipher.ENCRYPT_MODE, rsaPub);
        byte[] cipherText = cp.doFinal(plainText);

        // Verify the text
        cp.init(Cipher.DECRYPT_MODE, rsaPriv);
        byte[] newPlainText = cp.doFinal(cipherText);

        boolean success = decryptResultsMatch(cp.getAlgorithm(), plainText, newPlainText);
        assertTrue("Decrypted text does not match expected", success);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_keynull() throws Exception {
        try {
            Cipher cp = Cipher.getInstance("RSA", providerName);
            cp.init(Cipher.ENCRYPT_MODE, (Key) null);
            fail("Did not get InvalidKeyException");
        } catch (InvalidKeyException e) {
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_key_sr() throws Exception {
        Cipher cp = Cipher.getInstance("RSA", providerName);
        cp.init(Cipher.ENCRYPT_MODE, rsaPub, new SecureRandom());
        byte[] cipherText = cp.doFinal(plainText);

        // Verify the text
        cp.init(Cipher.DECRYPT_MODE, rsaPriv, new SecureRandom());
        byte[] newPlainText = cp.doFinal(cipherText);

        boolean success = decryptResultsMatch(cp.getAlgorithm(), plainText, newPlainText);
        assertTrue("Decrypted text does not match expected", success);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_key_srnull() throws Exception {
        Cipher cp = Cipher.getInstance("RSA", providerName);
        cp.init(Cipher.ENCRYPT_MODE, rsaPub, (SecureRandom) null);
        byte[] cipherText = cp.doFinal(plainText);

        // Verify the text
        cp.init(Cipher.DECRYPT_MODE, rsaPriv, (SecureRandom) null);
        byte[] newPlainText = cp.doFinal(cipherText);

        boolean success = decryptResultsMatch(cp.getAlgorithm(), plainText, newPlainText);
        assertTrue("Decrypted text does not match expected", success);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_key_algparms() throws Exception {
        // FIXME
        //AlgorithmParameters algParams = ??;
        //Cipher cp = Cipher.getInstance("RSA", providerName);
        //cp.init(Cipher.ENCRYPT_MODE, rsaPub, algParams);
        //byte[] cipherText = cp.doFinal(plainText);

        //// Verify the text
        //cp.init(Cipher.DECRYPT_MODE, rsaPriv, algParams);
        //byte[] newPlainText = cp.doFinal(cipherText);

        //boolean success = decryptResultsMatch(cp.getAlgorithm(), plainText, newPlainText);
        //assertTrue("Decrypted text does not match expected", success);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_key_algparmsnull() throws Exception {
        Cipher cp = Cipher.getInstance("RSA", providerName);
        cp.init(Cipher.ENCRYPT_MODE, rsaPub, (AlgorithmParameters) null);
        byte[] cipherText = cp.doFinal(plainText);

        // Verify the text
        cp.init(Cipher.DECRYPT_MODE, rsaPriv, (AlgorithmParameters) null);
        byte[] newPlainText = cp.doFinal(cipherText);

        boolean success = decryptResultsMatch(cp.getAlgorithm(), plainText, newPlainText);
        assertTrue("Decrypted text does not match expected", success);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_key_algparmspec() throws Exception {
        String transformation = "RSA/ECB/OAEPPadding";
        AlgorithmParameterSpec algParams = new OAEPParameterSpec("SHA-1",
                                                                 "MGF1",
                                                                 MGF1ParameterSpec.SHA1,
                                                                 PSource.PSpecified.DEFAULT);

        byte[] message = getMessage_OAEP_SHA1();
        if (message != null) {
            doTestRSACipher_init_key_algparmspec_oaep(transformation, algParams, message);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_key_algparmspec_SHA1() throws Exception {
        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS does not support SHA1
            return;
        }

        String oaepHashAlgorithm = "SHA-1";
        String transformation = "RSA/ECB/OAEPWith" + oaepHashAlgorithm + "AndMGF1Padding";
        AlgorithmParameterSpec algParams = new OAEPParameterSpec(oaepHashAlgorithm, "MGF1",
                MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
        byte[] message = getMessage_OAEP_SHA1();
        if (message != null) {
            doTestRSACipher_init_key_algparmspec_oaep(transformation, algParams, message);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_key_algparmspec_SHA224() throws Exception {
        String oaepHashAlgorithm = "SHA-224";
        String transformation = "RSA/ECB/OAEPWith" + oaepHashAlgorithm + "AndMGF1Padding";
        AlgorithmParameterSpec algParams = new OAEPParameterSpec(oaepHashAlgorithm, "MGF1",
                MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
        byte[] message = getMessage_OAEP_SHA224();
        if (message != null) {
            doTestRSACipher_init_key_algparmspec_oaep(transformation, algParams, message);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_key_algparmspec_SHA256() throws Exception {
        String oaepHashAlgorithm = "SHA-256";
        String transformation = "RSA/ECB/OAEPWith" + oaepHashAlgorithm + "AndMGF1Padding";
        AlgorithmParameterSpec algParams = new OAEPParameterSpec(oaepHashAlgorithm, "MGF1",
                MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
        byte[] message = getMessage_OAEP_SHA256();
        if (message != null) {
            doTestRSACipher_init_key_algparmspec_oaep(transformation, algParams, message);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_key_algparmspec_SHA384() throws Exception {
        String oaepHashAlgorithm = "SHA-384";
        String transformation = "RSA/ECB/OAEPWith" + oaepHashAlgorithm + "AndMGF1Padding";
        AlgorithmParameterSpec algParams = new OAEPParameterSpec(oaepHashAlgorithm, "MGF1",
                MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
        byte[] message = getMessage_OAEP_SHA384();
        if (message != null) {
            doTestRSACipher_init_key_algparmspec_oaep(transformation, algParams, message);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_key_algparmspec_SHA512() throws Exception {
        String oaepHashAlgorithm = "SHA-512";
        String transformation = "RSA/ECB/OAEPWith" + oaepHashAlgorithm + "AndMGF1Padding";
        AlgorithmParameterSpec algParams = new OAEPParameterSpec(oaepHashAlgorithm, "MGF1",
                MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
        byte[] message = getMessage_OAEP_SHA512();
        if (message != null) {
            doTestRSACipher_init_key_algparmspec_oaep(transformation, algParams, message);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void doTestRSACipher_init_key_algparmspec_oaep(String transformation,
            AlgorithmParameterSpec algParams, byte[] message) throws Exception {
        if (isTransformationValidButUnsupported(transformation)) {
            return;
        }

        Cipher cp = Cipher.getInstance(transformation, providerName);
        cp.init(Cipher.ENCRYPT_MODE, rsaPub, algParams);
        byte[] cipherText = cp.doFinal(message);

        // Verify the text
        cp.init(Cipher.DECRYPT_MODE, rsaPriv, algParams);
        byte[] newPlainText = cp.doFinal(cipherText);

        boolean success = decryptResultsMatch(cp.getAlgorithm(), message, newPlainText);
        assertTrue("Decrypted text does not match expected", success);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSACipher_init_key_algparmspecnull() throws Exception {
        Cipher cp = Cipher.getInstance("RSA", providerName);
        cp.init(Cipher.ENCRYPT_MODE, rsaPub, (AlgorithmParameterSpec) null);
        byte[] cipherText = cp.doFinal(plainText);

        // Verify the text
        cp.init(Cipher.DECRYPT_MODE, rsaPriv, (AlgorithmParameterSpec) null);
        byte[] newPlainText = cp.doFinal(cipherText);

        boolean success = decryptResultsMatch(cp.getAlgorithm(), plainText, newPlainText);
        assertTrue("Decrypted text does not match expected", success);
    }



    //--------------------------------------------------------------------------
    //
    //
    public void decryptDoFinalOutLen() throws Exception {

        String algorithm = "RSA";
        String keyType = "RSA";
        int keySize = 512;

        try {
            KeyPairGenerator RSAKeyPairGenerator = KeyPairGenerator.getInstance(keyType,
                    providerName);
            RSAKeyPairGenerator.initialize(keySize);
            KeyPair keyPair = RSAKeyPairGenerator.generateKeyPair();

            Key publicKey = keyPair.getPublic();
            Cipher cipher = Cipher.getInstance(algorithm, providerName);

            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] cipherText1 = cipher.update(plainText);
            byte[] cipherText2 = cipher.doFinal();

            byte[] encrpytedByteData = new byte[cipherText1.length + cipherText2.length];
            System.arraycopy(cipherText1, 0, encrpytedByteData, 0, cipherText1.length);
            System.arraycopy(cipherText2, 0, encrpytedByteData, cipherText1.length,
                    cipherText2.length);

            RSAKeyPairGenerator = KeyPairGenerator.getInstance(keyType, providerName);
            RSAKeyPairGenerator.initialize(keySize);
            keyPair = RSAKeyPairGenerator.generateKeyPair();

            Key privateKey = keyPair.getPrivate();

            byte iv[] = cipher.getIV();
            IvParameterSpec ivspec = null;
            if (iv != null) {
                ivspec = new IvParameterSpec(iv);
            }
            cipher.init(Cipher.DECRYPT_MODE, privateKey, ivspec);
            cipher.update(encrpytedByteData);
            cipher.doFinal();

            fail("Expected BadPaddingException did not occur");

        } catch (BadPaddingException ex) {
            assertTrue(true);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    protected void encryptDecrypt(String algorithm) throws Exception {
        encryptDecryptDoFinal(algorithm, plainText);
        encryptDecryptUpdate(algorithm, plainText);
        encryptDecryptPartialUpdate(algorithm, plainText);
    }

    //--------------------------------------------------------------------------
    //
    //
    protected void encryptDecrypt(String algorithm, byte[] message) throws Exception {
        encryptDecryptDoFinal(algorithm, message);
        encryptDecryptUpdate(algorithm, message);
        encryptDecryptPartialUpdate(algorithm, message);
    }

    //--------------------------------------------------------------------------
    //
    //
    protected void encryptDecryptDoFinal(String algorithm, byte[] message) throws Exception {

        if (isTransformationValidButUnsupported(algorithm)) {
            return;
        }

        Cipher cp = Cipher.getInstance(algorithm, providerName);

        // Encrypt the plain text
        cp.init(Cipher.ENCRYPT_MODE, rsaPub);
        byte[] cipherText = cp.doFinal(message);

        // Verify the text
        cp.init(Cipher.DECRYPT_MODE, rsaPriv);
        byte[] newPlainText = cp.doFinal(cipherText);

        boolean success = decryptResultsMatch(cp.getAlgorithm(), message, newPlainText);
        assertTrue("Decrypted text does not match expected", success);
    }

    //--------------------------------------------------------------------------
    //
    //
    protected void encryptDecryptUpdate(String algorithm, byte[] message) throws Exception {

        if (isTransformationValidButUnsupported(algorithm)) {
            return;
        }

        Cipher cp = Cipher.getInstance(algorithm, providerName);

        // Encrypt the plain text
        cp.init(Cipher.ENCRYPT_MODE, rsaPub);
        cp.update(message);
        byte[] cipherText = cp.doFinal();

        // Verify the text
        cp.init(Cipher.DECRYPT_MODE, rsaPriv);
        cp.update(cipherText);
        byte[] newPlainText = cp.doFinal();

        boolean success = decryptResultsMatch(cp.getAlgorithm(), message, newPlainText);
        assertTrue("Decrypted text does not match expected", success);
    }

    //--------------------------------------------------------------------------
    //
    //
    protected void encryptDecryptPartialUpdate(String algorithm, byte[] message) throws Exception {

        if (isTransformationValidButUnsupported(algorithm)) {
            return;
        }

        Cipher cp = Cipher.getInstance(algorithm, providerName);

        // Encrypt the plain text
        cp.init(Cipher.ENCRYPT_MODE, rsaPub);
        byte[] cipherText1 = cp.update(message, 0, 10);
        byte[] cipherText2 = cp.doFinal(message, 10, message.length - 10);

        // Verify the text
        cp.init(Cipher.DECRYPT_MODE, rsaPriv);
        byte[] newPlainText1 = cp.update(cipherText1);
        byte[] newPlainText2 = cp.doFinal(cipherText2);

        int l = (newPlainText1 == null) ? 0 : newPlainText1.length;
        byte[] newPlainText = new byte[l + newPlainText2.length];

        if (l != 0) {
            System.arraycopy(newPlainText1, 0, newPlainText, 0, l);
        }
        System.arraycopy(newPlainText2, 0, newPlainText, l, newPlainText2.length);

        boolean success = decryptResultsMatch(cp.getAlgorithm(), message, newPlainText);
        assertTrue("Decrypted text does not match expected", success);
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

    //--------------------------------------------------------------------------
    // Check whether the range of bytes in the input array are all zeroes
    //
    private static boolean bytesAreZero(byte[] input, int offset, int length) {
        for (int index = 0; index < length; ++index) {
            if (input[offset + index] != 0x00) {
                return false;
            }
        }
        return true;
    }

    //--------------------------------------------------------------------------
    //
    //
    private boolean decryptResultsMatch(String algorithm, byte[] originalText, byte[] decryptText) {

        boolean isAlgorithmNoPadding = algorithm.endsWith("NoPadding");

        if (isAlgorithmNoPadding) {
            if (providerStripsLeadingZerosForNoPaddingDecrypt) {
                // Decrypted text will be the same size as the original unless the original had
                // leading zero bytes in which case they are not present in the decrypted text
                //
                return (decryptText.length <= originalText.length)
                        && bytesAreZero(originalText, 0, originalText.length - decryptText.length)
                        && byteEqual(originalText, originalText.length - decryptText.length,
                                decryptText, 0, decryptText.length);
            } else {
                // Decrypted text will be the original text with leading zero bytes if the
                // input was padded.
                //
                return (decryptText.length >= originalText.length)
                        && bytesAreZero(decryptText, 0, decryptText.length - originalText.length)
                        && byteEqual(originalText, 0, decryptText,
                                decryptText.length - originalText.length, originalText.length);

            }
        } else {
            return Arrays.equals(originalText, decryptText);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    private byte[] getMessage_OAEP_SHA1() {
        return getMessage_OAEP(20);
    }

    //--------------------------------------------------------------------------
    //
    //
    private byte[] getMessage_OAEP_SHA224() {
        return getMessage_OAEP(28);
    }

    //--------------------------------------------------------------------------
    //
    //
    private byte[] getMessage_OAEP_SHA256() {
        return getMessage_OAEP(32);
    }

    //--------------------------------------------------------------------------
    //
    //
    private byte[] getMessage_OAEP_SHA384() {
        return getMessage_OAEP(48);
    }

    //--------------------------------------------------------------------------
    //
    //
    private byte[] getMessage_OAEP_SHA512() {
        return getMessage_OAEP(64);
    }

    //--------------------------------------------------------------------------
    //
    //
    private byte[] getMessage_OAEP(int digestLen) {
        int keySize = specifiedKeySize;
        if (keySize == 0) {
            keySize = ((java.security.interfaces.RSAKey) rsaPub).getModulus().bitLength();
        }

        int maxDataSize = (keySize / 8) - 2 - 2 * digestLen;
        if (maxDataSize <= 0) {
            return null;
        }

        byte[] message = Arrays.copyOf(plainText, maxDataSize);
        return message;
    }

    //--------------------------------------------------------------------------
    //
    //
    public static String toString(byte[] b) {
        if (b == null) {
            return "(null)";
        }
        StringBuffer sb = new StringBuffer(b.length * 3);
        for (int i = 0; i < b.length; i++) {
            int k = b[i] & 0xff;
            if (i != 0) {
                sb.append(':');
            }
            sb.append(hexDigits[k >>> 4]);
            sb.append(hexDigits[k & 0xf]);
        }
        return sb.toString();
    }

    //--------------------------------------------------------------------------
    //
    //
    public static byte[] parse(String s) {
        try {
            int n = s.length();
            ByteArrayOutputStream out = new ByteArrayOutputStream(n / 3);
            StringReader r = new StringReader(s);
            while (true) {
                int b1 = nextNibble(r);
                if (b1 < 0) {
                    break;
                }
                int b2 = nextNibble(r);
                if (b2 < 0) {
                    throw new RuntimeException("Invalid string " + s);
                }
                int b = (b1 << 4) | b2;
                out.write(b);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // --------------------------------------------------------------------------
    // This method is to check whether an algorithm is valid for the cipher
    // but not supported by a given provider.
    //
    @Override
    public boolean isAlgorithmValidButUnsupported(String algorithm) {
        if (algorithm.equalsIgnoreCase("RSAwithNoPad") || algorithm.equalsIgnoreCase("RSAforSSL")) {
            return true;
        }

        return super.isAlgorithmValidButUnsupported(algorithm);
    }

    // --------------------------------------------------------------------------
    // This method is to check whether a padidng is valid for the cipher
    // but not supported by a given provider.
    //
    @Override
    public boolean isPaddingValidButUnsupported(String padding) {
        if (padding.equalsIgnoreCase("ZeroPadding")
                || padding.equalsIgnoreCase("OAEPWithSHA-224AndMGF1Padding")
                || padding.equalsIgnoreCase("OAEPWithSHA-256AndMGF1Padding")
                || padding.equalsIgnoreCase("OAEPWithSHA-384AndMGF1Padding")
                || padding.equalsIgnoreCase("OAEPWithSHA-512AndMGF1Padding")) {
            return true;
        }

        return super.isPaddingValidButUnsupported(padding);
    }

    //--------------------------------------------------------------------------
    //
    //
    private static int nextNibble(StringReader r) throws IOException {
        while (true) {
            int ch = r.read();
            if (ch == -1) {
                return -1;
            } else if ((ch >= '0') && (ch <= '9')) {
                return ch - '0';
            } else if ((ch >= 'a') && (ch <= 'f')) {
                return ch - 'a' + 10;
            } else if ((ch >= 'A') && (ch <= 'F')) {
                return ch - 'A' + 10;
            }
        }
    }
}

