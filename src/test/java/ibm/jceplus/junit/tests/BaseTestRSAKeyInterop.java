/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
public abstract class BaseTestRSAKeyInterop extends BaseTestInterop {

    @Parameter(0)
    TestProvider provider;

    @Parameter(1)
    TestProvider interopProvider;

    @Parameter(2)
    TestProvider interopProvider2;

    protected KeyPairGenerator rsaKeyPairGenPlus;
    protected KeyFactory rsaKeyFactoryPlus;
    protected KeyPairGenerator rsaKeyPairGenInterop;
    protected KeyFactory rsaKeyFactoryInterop;

    byte[] origMsg = "this is the original message to be signed".getBytes();

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
        setAndInsertInteropProvider(interopProvider);
        setAndInsertInteropProvider2(interopProvider2);
        setKeySize(2048);
        if (interopProvider == TestProvider.BC && !getProviderName().equals("OpenJCEPlusFIPS")) {
            setKeySize(1024);
        }
        rsaKeyPairGenPlus = KeyPairGenerator.getInstance("RSA", getProviderName());
        rsaKeyFactoryPlus = KeyFactory.getInstance("RSA", getProviderName());
        rsaKeyPairGenInterop = KeyPairGenerator.getInstance("RSA", getInteropProviderName());
        rsaKeyFactoryInterop = KeyFactory.getInstance("RSA", getInteropProviderName());
    }

    @Test
    public void testRSAKeyGen_PlusToInterop() throws Exception {
        KeyPair rsaKeyPairPlus = generateKeyPair(rsaKeyPairGenPlus, getKeySize());
        RSAPublicKey publicKeyPlus = (RSAPublicKey) rsaKeyPairPlus.getPublic();
        RSAPrivateKey privateKeyPlus = (RSAPrivateKey) rsaKeyPairPlus.getPrivate();
        byte[] publicKeyBytesPlus = publicKeyPlus.getEncoded();
        byte[] privateKeyBytesPlus = privateKeyPlus.getEncoded();

        //KeyFactory keyFactory = KeyFactory.getInstance("RSA", interopProviderName);
        EncodedKeySpec privateKeySpecPlus = new PKCS8EncodedKeySpec(privateKeyBytesPlus);
        EncodedKeySpec publicKeySpecPlus = new X509EncodedKeySpec(publicKeyBytesPlus);
        PublicKey publicKeyInterop = rsaKeyFactoryInterop.generatePublic(publicKeySpecPlus);
        PrivateKey privateKeyInterop = rsaKeyFactoryInterop.generatePrivate(privateKeySpecPlus);

        // The original and new keys are the same
        assertArrayEquals(privateKeyBytesPlus, privateKeyInterop.getEncoded());
        assertArrayEquals(publicKeyBytesPlus, publicKeyInterop.getEncoded());
        assertEquals(privateKeyPlus, privateKeyInterop);
        assertEquals(publicKeyPlus, publicKeyInterop);

    }

    @Test
    public void testRSAKeyGen_InteropToPlus() throws Exception {
        KeyPair rsaKeyPairInterop = generateKeyPair(rsaKeyPairGenInterop, getKeySize());
        RSAPublicKey publicKeyInterop = (RSAPublicKey) rsaKeyPairInterop.getPublic();
        RSAPrivateKey privateKeyInterop = (RSAPrivateKey) rsaKeyPairInterop.getPrivate();
        byte[] publicKeyBytesInterop = publicKeyInterop.getEncoded();
        byte[] privateKeyBytesInterop = privateKeyInterop.getEncoded();

        //KeyFactory keyFactory = KeyFactory.getInstance("RSA", interopProviderName);
        EncodedKeySpec privateKeySpecInterop = new PKCS8EncodedKeySpec(privateKeyBytesInterop);
        PrivateKey privateKeyPlus = rsaKeyFactoryPlus.generatePrivate(privateKeySpecInterop);

        EncodedKeySpec publicKeySpecInterop = new X509EncodedKeySpec(publicKeyBytesInterop);
        PublicKey publicKeyPlus = rsaKeyFactoryPlus.generatePublic(publicKeySpecInterop);

        // The original and new keys are the same
        assertArrayEquals(privateKeyBytesInterop, privateKeyPlus.getEncoded());
        assertArrayEquals(publicKeyBytesInterop, publicKeyPlus.getEncoded());
        assertEquals(privateKeyPlus, privateKeyInterop);
        assertEquals(publicKeyPlus, publicKeyInterop);

    }

    @Test
    public void testRSAKeyFactoryCreateFromEncodedInteropToPlus_1024() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            // 1024 key size for FIPS not supported
            return;
        }
        keyFactoryCreateFromEncodedInteropToPlus(1024);
    }

    @Test
    public void testRSAKeyFactoryCreateFromEncodedPlusToInterop_1024() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            // 1024 key size for FIPS not supported
            return;
        }
        keyFactoryCreateFromEncodedPlusToInterop(1024);
    }

    @Test
    public void testRSAKeyFactoryCreateFromKeySpecInteropToPlus_2048() throws Exception {
        keyFactoryCreateFromKeySpecInteropToPlus(2048);
    }

    @Test
    public void testRSAKeyFactoryCreateFromKeySpecPlusToInterop_2048() throws Exception {
        keyFactoryCreateFromKeySpecPlusToInterop(2048);
    }

    /*

    @Test
    public void testRSAKeyFactoryCreateFromKeySpec() throws Exception {

        RSAPrivateCrtKeySpec crtSpec = new RSAPrivateCrtKeySpec(
                new BigInteger("00BF6097526F553D345A702A86DA69A3C98379EFC52BD9246DBDD7F75B17CA115"+
                "102F379E5F59715D41F5A6FD5F8EE70E2ECD6813222FF1E45D7742C5E823C3BE382AFC564701B83D674F463"+
                "04290456408E7CD638322F3D461AFB6B8529AD3A7902CA12E8AF9D8F5C267A930CFFD9E13B3A12CDE2784C"+
                "2E797572A344C3698327",16),
                new BigInteger("010001",16),
                new BigInteger("35067FD704E702BED34219DE647CF9B737791D30ADFE0BC4666204F4D5EA149334349E"+
                "F552EF4A4A8C6763EE4EFB4E06EA256305AFC1AD331FC7DE154F937DEA07F83D60ED645167EFBF19357B6BF593DA1BAD"+
                "640FA1C230771970AADF94AAF75636DEDC3D8795E50242101866A9D99620193C46921F8542688D8F377593BD0D",16),
                new BigInteger("00F559F092F829CDF2224C2C106F1CDFA0AF3EF5EAF22687EE1FB34E0BD6816D91"+
                "45D0D618BE63B88B7483C9B2ABB9CE5836D22A5700B03B8F5923723C26F0A193",16),
                new BigInteger("00C7AEF458A31A1C85B72ED67DE9EA7E95E52092C5E6B43E03AD930CBA60"+
                "81DE583060A728DA778FC4405FF06B4C8EE1943E7E9DA3F33110E1870A1099CA03649D",16),
                new BigInteger("00DA359E9827EC8E44EEAA0E7AA347EBC06E7C319D3EB674289DBB"+
                "0C0BCD4099611DD5C9C481F810D6BECEC3218C4799B4AD352800EF14CE3404D458B214F3E8CF",16),
                new BigInteger("00916B20F937F679150BFD69291363B9421235F18D7BE081"+
                "550E600BA1E34C508F2AD4088820E97762757B28CC0B59F67F8E2F893FEF88290204E4D88816ECF7A5",16),
                new BigInteger("05A8AA2383DE604F6A77AFDBC88B517226434F2E331261484A11128F1D6ED29D068A20B7B1"+
                "48219A23BD70BF9FAEE7AA795D5A8537C90E88D3E4F8CA146907CB",16));

        RSAPrivateCrtKey rsaPriv = (RSAPrivateCrtKey) rsaKeyFactory.generatePrivate(crtSpec);

        RSAPublicKeySpec rsaPublicSpec = new RSAPublicKeySpec(rsaPriv.getModulus(), rsaPriv.getPublicExponent());
        RSAPublicKey rsaPub = (RSAPublicKey) rsaKeyFactory.generatePublic(rsaPublicSpec);
    }
    */

    protected KeyPair generateKeyPair(KeyPairGenerator keyPairGen, int size) throws Exception {
        keyPairGen.initialize(size);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        if (keyPair.getPrivate() == null) {
            fail("RSA Private key is null");
        }

        if (keyPair.getPublic() == null) {
            fail("RSA Public key is null");
        }

        if (!(keyPair.getPrivate() instanceof RSAPrivateKey)) {
            fail("Private key is not a RSAPrivateKey");
        }

        if (!(keyPair.getPublic() instanceof RSAPublicKey)) {
            fail("Private key is not a RSAPublicKey");
        }

        return keyPair;
    }


    protected void keyFactoryCreateFromEncodedPlusToInterop(int size) throws Exception {

        KeyPair rsaKeyPairPlus = generateKeyPair(rsaKeyPairGenPlus, size);

        X509EncodedKeySpec x509SpecPlus = new X509EncodedKeySpec(
                rsaKeyPairPlus.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8SpecPlus = new PKCS8EncodedKeySpec(
                rsaKeyPairPlus.getPrivate().getEncoded());

        RSAPublicKey rsaPubPlus = (RSAPublicKey) rsaKeyFactoryPlus.generatePublic(x509SpecPlus);
        RSAPrivateKey rsaPrivPlus = (RSAPrivateKey) rsaKeyFactoryPlus
                .generatePrivate(pkcs8SpecPlus);

        if (!Arrays.equals(rsaPubPlus.getEncoded(), rsaKeyPairPlus.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }
        assertEquals(rsaKeyPairPlus.getPublic(), rsaPubPlus);

        if (!Arrays.equals(rsaPrivPlus.getEncoded(), rsaKeyPairPlus.getPrivate().getEncoded())) {
            fail("RSA private key does not match generated public key");
        }
        assertEquals(rsaKeyPairPlus.getPrivate(), rsaPrivPlus);

        //KeyPair rsaKeyPairInterOp = generateKeyPair(rsaKeyPairGenInterOp, size);

        //X509EncodedKeySpec  x509SpecInterOp  = new X509EncodedKeySpec(rsaPub.getEncoded());
        //PKCS8EncodedKeySpec pkcs8SpecInterOp = new PKCS8EncodedKeySpec(rsaPriv.getEncoded());

        //Test Interop  with JCE

        RSAPublicKey rsaPubInterop = (RSAPublicKey) rsaKeyFactoryInterop.generatePublic(x509SpecPlus);
        RSAPrivateKey rsaPrivInterop = (RSAPrivateKey) rsaKeyFactoryInterop.generatePrivate(pkcs8SpecPlus);
        if (!Arrays.equals(rsaPubInterop.getEncoded(), rsaKeyPairPlus.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }
        assertEquals(rsaKeyPairPlus.getPublic(), rsaPubInterop);

        //System.out.println ("RSAPrivInterOp get Bytes " + toHex(rsaPrivInterop.getEncoded()));
        //System.out.println ("rsaKeyPair.getPrivate().getEncoded() get Bytes " + toHex(rsaKeyPairPlus.getPrivate().getEncoded()));
        if (!Arrays.equals(rsaPrivInterop.getEncoded(), rsaKeyPairPlus.getPrivate().getEncoded())) {
            fail("RSA private key does not match generated private key");
        }
        assertEquals(rsaKeyPairPlus.getPrivate(), rsaPrivInterop);

    }

    protected void keyFactoryCreateFromEncodedInteropToPlus(int size) throws Exception {

        KeyPair rsaKeyPairInterop = generateKeyPair(rsaKeyPairGenInterop, size);

        X509EncodedKeySpec x509SpecInterop = new X509EncodedKeySpec(
                rsaKeyPairInterop.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8SpecInterop = new PKCS8EncodedKeySpec(
                rsaKeyPairInterop.getPrivate().getEncoded());

        RSAPublicKey rsaPubInterop = (RSAPublicKey) rsaKeyFactoryInterop.generatePublic(x509SpecInterop);
        RSAPrivateKey rsaPrivInterop = (RSAPrivateKey) rsaKeyFactoryInterop.generatePrivate(pkcs8SpecInterop);

        if (!Arrays.equals(rsaPubInterop.getEncoded(), rsaKeyPairInterop.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }

        if (!Arrays.equals(rsaPrivInterop.getEncoded(), rsaKeyPairInterop.getPrivate().getEncoded())) {
            fail("RSA private key does not match generated public key");
        }

        //KeyPair rsaKeyPairInterOp = generateKeyPair(rsaKeyPairGenInterOp, size);
        //X509EncodedKeySpec  x509Spec = new X509EncodedKeySpec(rsaPubInterOp.getEncoded());
        //PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(rsaPrivInterOp.getEncoded());

        RSAPublicKey rsaPubPlus = (RSAPublicKey) rsaKeyFactoryPlus.generatePublic(x509SpecInterop);
        RSAPrivateKey rsaPrivPlus = (RSAPrivateKey) rsaKeyFactoryPlus.generatePrivate(pkcs8SpecInterop);
        if (!Arrays.equals(rsaPubPlus.getEncoded(), rsaKeyPairInterop.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }
        assertEquals(rsaPubPlus, rsaKeyPairInterop.getPublic());

        //System.out.println ("RSAPrivInterOp get Bytes " + toHex(rsaPrivPlus.getEncoded()));
        //System.out.println ("rsaKeyPairInterop.getPrivate().getEncoded() get Bytes " + toHex(rsaKeyPairInterop.getPrivate().getEncoded()));
        if (!Arrays.equals(rsaPrivPlus.getEncoded(), rsaKeyPairInterop.getPrivate().getEncoded())) {
            fail("RSA private key does not match generated private key");
        }
        assertEquals(rsaPrivPlus, rsaKeyPairInterop.getPrivate());

    }



    protected void keyFactoryCreateFromKeySpecInteropToPlus(int size) throws Exception {

        KeyPair rsaKeyPairInterop = generateKeyPair(rsaKeyPairGenInterop, size);

        RSAPublicKeySpec rsaPubSpecInterop = rsaKeyFactoryInterop
                .getKeySpec(rsaKeyPairInterop.getPublic(), RSAPublicKeySpec.class);
        RSAPublicKey rsaPubInterop = (RSAPublicKey) rsaKeyFactoryInterop.generatePublic(rsaPubSpecInterop);

        if (!Arrays.equals(rsaPubInterop.getEncoded(), rsaKeyPairInterop.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }

        if (rsaKeyPairInterop.getPrivate() instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKeySpec rsaPrivateCrtSpecInterop = rsaKeyFactoryInterop
                    .getKeySpec(rsaKeyPairInterop.getPrivate(), RSAPrivateCrtKeySpec.class);
            RSAPrivateCrtKey rsaPrivCrtInterop = (RSAPrivateCrtKey) rsaKeyFactoryInterop
                    .generatePrivate(rsaPrivateCrtSpecInterop);

            if (!Arrays.equals(rsaPrivCrtInterop.getEncoded(), rsaPrivCrtInterop.getEncoded())) {
                fail("RSA private CRT key does not match generated private key");
            }

            RSAPrivateKeySpec rsaPrivateSpecInterop = rsaKeyFactoryInterop
                    .getKeySpec(rsaPrivCrtInterop, RSAPrivateKeySpec.class);
            try {
                rsaKeyFactoryInterop.generatePrivate(rsaPrivateSpecInterop);
            } catch (InvalidKeySpecException ikse) {
                assertTrue(false, "JCEPlus InvalidKeySpeccException = " + ikse.getMessage());
            }
        } else {
            RSAPrivateKeySpec rsaPrivateSpecInterop = rsaKeyFactoryInterop
                    .getKeySpec(rsaKeyPairInterop.getPrivate(), RSAPrivateKeySpec.class);
            RSAPrivateKey rsaPrivInterop = (RSAPrivateKey) rsaKeyFactoryInterop
                    .generatePrivate(rsaPrivateSpecInterop);

            if (!Arrays.equals(rsaPrivInterop.getEncoded(), rsaKeyPairInterop.getPrivate().getEncoded())) {
                fail("RSA private key does not match generated private key");
            }
        }
    }

    protected void keyFactoryCreateFromKeySpecPlusToInterop(int size) throws Exception {

        KeyPair rsaKeyPairPlus = generateKeyPair(rsaKeyPairGenPlus, size);

        RSAPublicKeySpec rsaPubSpecPlus = rsaKeyFactoryPlus
                .getKeySpec(rsaKeyPairPlus.getPublic(), RSAPublicKeySpec.class);
        RSAPublicKey rsaPubPlus = (RSAPublicKey) rsaKeyFactoryPlus.generatePublic(rsaPubSpecPlus);

        if (!Arrays.equals(rsaPubPlus.getEncoded(), rsaKeyPairPlus.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }

        if (rsaKeyPairPlus.getPrivate() instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKeySpec rsaPrivateCrtSpecPlus = rsaKeyFactoryPlus
                    .getKeySpec(rsaKeyPairPlus.getPrivate(), RSAPrivateCrtKeySpec.class);
            RSAPrivateCrtKey rsaPrivCrtPlus = (RSAPrivateCrtKey) rsaKeyFactoryPlus
                    .generatePrivate(rsaPrivateCrtSpecPlus);

            if (!Arrays.equals(rsaPrivCrtPlus.getEncoded(),
                    rsaKeyPairPlus.getPrivate().getEncoded())) {
                fail("RSA private CRT key does not match generated private key");
            }

            RSAPrivateKeySpec rsaPrivateSpecPlus = rsaKeyFactoryPlus
                    .getKeySpec(rsaKeyPairPlus.getPrivate(), RSAPrivateKeySpec.class);
            try {

                rsaKeyFactoryPlus.generatePrivate(rsaPrivateSpecPlus);
            } catch (InvalidKeySpecException ikse) {
                assertTrue(false, "JCEPlus InvalidKeySpeccException = " + ikse.getMessage());
            }
        } else {
            RSAPrivateKeySpec rsaPrivateSpecPlus = rsaKeyFactoryPlus
                    .getKeySpec(rsaKeyPairPlus.getPrivate(), RSAPrivateKeySpec.class);
            RSAPrivateKey rsaPrivPlus = (RSAPrivateKey) rsaKeyFactoryPlus
                    .generatePrivate(rsaPrivateSpecPlus);

            if (!Arrays.equals(rsaPrivPlus.getEncoded(),
                    rsaKeyPairPlus.getPrivate().getEncoded())) {
                fail("RSA private key does not match generated private key");
            }
        }
    }

    @Test
    public void testSignInteropAndVerifyPlus() {
        try {

            rsaKeyPairGenInterop.initialize(getKeySize());
            KeyPair rsaKeyPairInterop = rsaKeyPairGenInterop.generateKeyPair();

            rsaKeyPairInterop.getPublic();
            RSAPrivateKey rsaPrivInterop = (RSAPrivateKey) rsaKeyPairInterop.getPrivate();
            Signature signingInterop = Signature.getInstance("SHA256WithRSA", getInteropProviderName());
            signingInterop.initSign(rsaPrivInterop);
            signingInterop.update(origMsg);
            byte[] signedBytesInterop = signingInterop.sign();

            X509EncodedKeySpec x509SpecInterop = new X509EncodedKeySpec(
                    rsaKeyPairInterop.getPublic().getEncoded());
            PKCS8EncodedKeySpec pkcs8SpecInterop = new PKCS8EncodedKeySpec(
                    rsaKeyPairInterop.getPrivate().getEncoded());

            RSAPublicKey rsaPubPlus = (RSAPublicKey) rsaKeyFactoryPlus.generatePublic(x509SpecInterop);
            rsaKeyFactoryPlus.generatePrivate(pkcs8SpecInterop);

            Signature verifyingPlus = Signature.getInstance("SHA256withRSA", getProviderName());
            verifyingPlus.initVerify(rsaPubPlus);
            verifyingPlus.update(origMsg);
            assertTrue(verifyingPlus.verify(signedBytesInterop), "Signature verification failed");
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "signInteropAndVerifyPlus failed");
        }
    }

    @Test
    public void testSignInteropAndVerifyPlusPrivateCrt() {

        try {

            rsaKeyPairGenInterop.initialize(getKeySize());
            KeyPair rsaKeyPairInterop = rsaKeyPairGenInterop.generateKeyPair();

            rsaKeyPairInterop.getPublic();
            RSAPrivateCrtKey rsaPrivInterop = (RSAPrivateCrtKey) rsaKeyPairInterop.getPrivate();
            Signature signingInterop = Signature.getInstance("SHA256WithRSA", getInteropProviderName());
            signingInterop.initSign(rsaPrivInterop);
            signingInterop.update(origMsg);
            byte[] signedBytesInterop = signingInterop.sign();

            X509EncodedKeySpec x509SpecInterop = new X509EncodedKeySpec(
                    rsaKeyPairInterop.getPublic().getEncoded());
            PKCS8EncodedKeySpec pkcs8SpecInterop = new PKCS8EncodedKeySpec(
                    rsaKeyPairInterop.getPrivate().getEncoded());

            RSAPublicKey rsaPubPlus = (RSAPublicKey) rsaKeyFactoryPlus.generatePublic(x509SpecInterop);
            rsaKeyFactoryPlus.generatePrivate(pkcs8SpecInterop);

            Signature verifyingPlus = Signature.getInstance("SHA256withRSA", getProviderName());
            verifyingPlus.initVerify(rsaPubPlus);
            verifyingPlus.update(origMsg);
            assertTrue(verifyingPlus.verify(signedBytesInterop), "Signature verification failed");
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "signInteropAndVerifyPlus failed");
        }
    }

    @Test
    public void testSignPlusAndVerifyInterop() {

        try {
            rsaKeyPairGenPlus.initialize(getKeySize());
            KeyPair rsaKeyPairPlus = rsaKeyPairGenPlus.generateKeyPair();

            rsaKeyPairPlus.getPublic();
            RSAPrivateKey rsaPrivPlus = (RSAPrivateKey) rsaKeyPairPlus.getPrivate();
            Signature signingPlus = Signature.getInstance("SHA256WithRSA", getProviderName());
            signingPlus.initSign(rsaPrivPlus);
            signingPlus.update(origMsg);
            byte[] signedBytesPlus = signingPlus.sign();

            X509EncodedKeySpec x509SpecPlus = new X509EncodedKeySpec(
                    rsaKeyPairPlus.getPublic().getEncoded());
            PKCS8EncodedKeySpec pkcs8SpecPlus = new PKCS8EncodedKeySpec(
                    rsaKeyPairPlus.getPrivate().getEncoded());

            RSAPublicKey rsaPubInterop = (RSAPublicKey) rsaKeyFactoryInterop.generatePublic(x509SpecPlus);
            rsaKeyFactoryInterop.generatePrivate(pkcs8SpecPlus);

            Signature verifyingInterop = Signature.getInstance("SHA256withRSA", getInteropProviderName());
            verifyingInterop.initVerify(rsaPubInterop);
            verifyingInterop.update(origMsg);
            assertTrue(verifyingInterop.verify(signedBytesPlus), "Signature verification");
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "SignAndVerify failed");
        }
    }

    @Test
    public void testSignPlusAndVerifyInteropCrt() {
        try {

            rsaKeyPairGenPlus.initialize(getKeySize());
            KeyPair rsaKeyPairPlus = rsaKeyPairGenPlus.generateKeyPair();

            rsaKeyPairPlus.getPublic();
            RSAPrivateCrtKey rsaPrivPlus = (RSAPrivateCrtKey) rsaKeyPairPlus.getPrivate();
            Signature signingPlus = Signature.getInstance("SHA256WithRSA", getProviderName());
            signingPlus.initSign(rsaPrivPlus);
            signingPlus.update(origMsg);
            byte[] signedBytesPlus = signingPlus.sign();

            X509EncodedKeySpec x509SpecPlus = new X509EncodedKeySpec(
                    rsaKeyPairPlus.getPublic().getEncoded());
            PKCS8EncodedKeySpec pkcs8SpecPlus = new PKCS8EncodedKeySpec(
                    rsaKeyPairPlus.getPrivate().getEncoded());

            RSAPublicKey rsaPubInterop = (RSAPublicKey) rsaKeyFactoryInterop.generatePublic(x509SpecPlus);
            rsaKeyFactoryInterop.generatePrivate(pkcs8SpecPlus);

            Signature verifyingInterop = Signature.getInstance("SHA256withRSA", getProviderName());
            verifyingInterop.initVerify(rsaPubInterop);
            verifyingInterop.update(origMsg);
            assertTrue(verifyingInterop.verify(signedBytesPlus), "Signature verification failed");
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue( false, "signPlusAndVerifyInterop failed");
        }
    }

    @Test
    public void testEncryptPlusDecryptInterop() {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        try {

            byte[] msgBytes = ("This is a short msg".getBytes());
            //            public and Private key;" +
            //                "encrypt with JCE and d/ecrypt with JCEPlus and vice versa").getBytes();
            byte[] cipherText;
            rsaKeyPairGenPlus.initialize(getKeySize());
            KeyPair rsaKeyPairPlus = rsaKeyPairGenPlus.generateKeyPair();

            RSAPublicKey rsaPubPlus = (RSAPublicKey) rsaKeyPairPlus.getPublic();
            rsaKeyPairPlus.getPrivate();
            Cipher cipherPlus = Cipher.getInstance("RSA/ECB/PKCS1Padding", getProviderName());
            cipherPlus.init(Cipher.ENCRYPT_MODE, rsaPubPlus);
            cipherText = cipherPlus.doFinal(msgBytes);

            X509EncodedKeySpec x509SpecPlus = new X509EncodedKeySpec(
                    rsaKeyPairPlus.getPublic().getEncoded());
            PKCS8EncodedKeySpec pkcs8SpecPlus = new PKCS8EncodedKeySpec(
                    rsaKeyPairPlus.getPrivate().getEncoded());

            rsaKeyFactoryInterop.generatePublic(x509SpecPlus);
            RSAPrivateCrtKey rsaPrivInterop = (RSAPrivateCrtKey) rsaKeyFactoryInterop
                    .generatePrivate(pkcs8SpecPlus);

            Cipher cipherInterop = Cipher.getInstance("RSA/ECB/PKCS1Padding", getInteropCipherProviderName());
            cipherInterop.init(Cipher.DECRYPT_MODE, rsaPrivInterop);
            byte[] decryptedBytes = cipherInterop.doFinal(cipherText);
            System.out.println("msgBytes = " + toHex(msgBytes));
            System.out.println("decryptedBytes = " + toHex(decryptedBytes));
            assertTrue(Arrays.equals(msgBytes, decryptedBytes));
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "testEncryptPlusDecryptInterop");
        }
    }

    @Test
    public void testEncryptInteropDecryptPlus() {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        byte[] msgBytes = ("This is a short message".getBytes());
        //long message to be encrypted and decrypted using RSA public and Private key;" +
        //        "encrypt with JCE and decrypt with JCEPlus and vice versa").getBytes();

        try {
            byte[] cipherText;
            rsaKeyPairGenInterop.initialize(getKeySize());
            KeyPair rsaKeyPairInterop = rsaKeyPairGenInterop.generateKeyPair();

            RSAPublicKey rsaPubInterop = (RSAPublicKey) rsaKeyPairInterop.getPublic();
            rsaKeyPairInterop.getPrivate();
            Cipher cipherInterop = Cipher.getInstance("RSA/ECB/PKCS1Padding", getProviderName());
            cipherInterop.init(Cipher.ENCRYPT_MODE, rsaPubInterop);
            cipherText = cipherInterop.doFinal(msgBytes);

            X509EncodedKeySpec x509SpecInterop = new X509EncodedKeySpec(
                    rsaKeyPairInterop.getPublic().getEncoded());
            PKCS8EncodedKeySpec pkcs8SpecInterop = new PKCS8EncodedKeySpec(
                    rsaKeyPairInterop.getPrivate().getEncoded());

            rsaKeyFactoryPlus.generatePublic(x509SpecInterop);
            RSAPrivateCrtKey rsaPrivPlus = (RSAPrivateCrtKey) rsaKeyFactoryPlus
                    .generatePrivate(pkcs8SpecInterop);

            Cipher cipherPlus = Cipher.getInstance("RSA/ECB/PKCS1Padding", getInteropCipherProviderName());
            cipherPlus.init(Cipher.DECRYPT_MODE, rsaPrivPlus);
            byte[] decryptedBytes = cipherPlus.doFinal(cipherText);
            System.out.println("msgBytes = " + toHex(msgBytes));
            System.out.println("decryptedBytes = " + toHex(decryptedBytes));
            assertTrue(Arrays.equals(msgBytes, decryptedBytes));
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, " testEncryptInteropDecryptPlus");
        }
    }

    /**
     * Gets the provider used for the cipher that handles keys created by the interop provider.
     */
    protected String getInteropCipherProviderName() {
        if (interopProvider == TestProvider.BC) {
            return getProviderName();
        }
        return getInteropProviderName2();
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

