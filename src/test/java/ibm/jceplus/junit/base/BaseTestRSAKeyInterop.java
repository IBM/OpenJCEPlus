/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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

public class BaseTestRSAKeyInterop extends BaseTestInterop {

    //--------------------------------------------------------------------------
    //
    //
    protected KeyPairGenerator rsaKeyPairGenPlus;
    protected KeyFactory rsaKeyFactoryPlus;
    protected KeyPairGenerator rsaKeyPairGenJCE;
    protected KeyFactory rsaKeyFactoryJCE;
    protected int keySize = 1024;

    byte[] origMsg = "this is the original message to be signed".getBytes();

    //--------------------------------------------------------------------------
    //
    //
    public BaseTestRSAKeyInterop(String providerName, String interopProviderName) {
        super(providerName, interopProviderName);
    }

    public BaseTestRSAKeyInterop(String providerName, String interopProviderName, int size) {
        super(providerName, interopProviderName);
        this.keySize = size;
    }

    //--------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {
        rsaKeyPairGenPlus = KeyPairGenerator.getInstance("RSA", providerName);
        rsaKeyFactoryPlus = KeyFactory.getInstance("RSA", providerName);
        rsaKeyPairGenJCE = KeyPairGenerator.getInstance("RSA", interopProviderName);
        rsaKeyFactoryJCE = KeyFactory.getInstance("RSA", interopProviderName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    //--------------------------------------------------------------------------
    //
    //
    public void testRSAKeyGen_PlusToJCE() throws Exception {
        KeyPair rsaKeyPairPlus = generateKeyPair(rsaKeyPairGenPlus, this.keySize);
        RSAPublicKey publicKeyPlus = (RSAPublicKey) rsaKeyPairPlus.getPublic();
        RSAPrivateKey privateKeyPlus = (RSAPrivateKey) rsaKeyPairPlus.getPrivate();
        byte[] publicKeyBytesPlus = publicKeyPlus.getEncoded();
        byte[] privateKeyBytesPlus = privateKeyPlus.getEncoded();

        //KeyFactory keyFactory = KeyFactory.getInstance("RSA", interopProviderName);
        EncodedKeySpec privateKeySpecPlus = new PKCS8EncodedKeySpec(privateKeyBytesPlus);
        EncodedKeySpec publicKeySpecPlus = new X509EncodedKeySpec(publicKeyBytesPlus);
        PublicKey publicKeyJCE = rsaKeyFactoryJCE.generatePublic(publicKeySpecPlus);
        PrivateKey privateKeyJCE = rsaKeyFactoryJCE.generatePrivate(privateKeySpecPlus);


        // The original and new keys are the same
        boolean same = privateKeyPlus.equals(privateKeyJCE);
        assertTrue(same);
        same = publicKeyPlus.equals(publicKeyJCE);
        assertTrue(same);

    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSAKeyGen_JCEToPlus() throws Exception {
        KeyPair rsaKeyPairJCE = generateKeyPair(rsaKeyPairGenJCE, this.keySize);
        RSAPublicKey publicKeyJCE = (RSAPublicKey) rsaKeyPairJCE.getPublic();
        RSAPrivateKey privateKeyJCE = (RSAPrivateKey) rsaKeyPairJCE.getPrivate();
        byte[] publicKeyBytesJCE = publicKeyJCE.getEncoded();
        byte[] privateKeyBytesJCE = privateKeyJCE.getEncoded();

        //KeyFactory keyFactory = KeyFactory.getInstance("RSA", interopProviderName);
        EncodedKeySpec privateKeySpecJCE = new PKCS8EncodedKeySpec(privateKeyBytesJCE);
        PrivateKey privateKeyPlus = rsaKeyFactoryPlus.generatePrivate(privateKeySpecJCE);

        EncodedKeySpec publicKeySpecJCE = new X509EncodedKeySpec(publicKeyBytesJCE);
        PublicKey publicKeyPlus = rsaKeyFactoryPlus.generatePublic(publicKeySpecJCE);

        // The original and new keys are the same
        boolean same = privateKeyPlus.equals(privateKeyJCE);
        assertTrue(same);
        same = publicKeyPlus.equals(publicKeyJCE);
        assertTrue(same);

    }


    //--------------------------------------------------------------------------
    //
    //
    public void testRSAKeyFactoryCreateFromEncodedJCEtoPlus_1024() throws Exception {
        if (providerName.equals("OpenJCEPlusFIPS")) {
            // 1024 key size for FIPS not supported
            return;
        }
        keyFactoryCreateFromEncodedJCEToPlus(1024);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSAKeyFactoryCreateFromEncodedPlusToJCE_1024() throws Exception {
        if (providerName.equals("OpenJCEPlusFIPS")) {
            // 1024 key size for FIPS not supported
            return;
        }
        keyFactoryCreateFromEncodedPlusToJCE(1024);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSAKeyFactoryCreateFromKeySpecJCEToPlus_2048() throws Exception {
        keyFactoryCreateFromKeySpecJCEToPlus(2048);
    }

    public void testRSAKeyFactoryCreateFromKeySpecPlusToJCE_2048() throws Exception {
        keyFactoryCreateFromKeySpecPlusToJCE(2048);
    }

    /*
    //--------------------------------------------------------------------------
    //
    //
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
    //--------------------------------------------------------------------------
    //
    //
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

    //--------------------------------------------------------------------------
    //
    //
    protected void keyFactoryCreateFromEncodedPlusToJCE(int size) throws Exception {

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

        if (!Arrays.equals(rsaPrivPlus.getEncoded(), rsaKeyPairPlus.getPrivate().getEncoded())) {
            fail("RSA private key does not match generated public key");
        }



        //KeyPair rsaKeyPairInterOp = generateKeyPair(rsaKeyPairGenInterOp, size);

        //X509EncodedKeySpec  x509SpecInterOp  = new X509EncodedKeySpec(rsaPub.getEncoded());
        //PKCS8EncodedKeySpec pkcs8SpecInterOp = new PKCS8EncodedKeySpec(rsaPriv.getEncoded());

        //Test Interop  with JCE

        RSAPublicKey rsaPubJCE = (RSAPublicKey) rsaKeyFactoryJCE.generatePublic(x509SpecPlus);
        RSAPrivateKey rsaPrivJCE = (RSAPrivateKey) rsaKeyFactoryJCE.generatePrivate(pkcs8SpecPlus);
        if (!Arrays.equals(rsaPubJCE.getEncoded(), rsaKeyPairPlus.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }

        //System.out.println ("RSAPrivInterOp get Bytes " + toHex(rsaPrivJCE.getEncoded()));
        //System.out.println ("rsaKeyPair.getPrivate().getEncoded() get Bytes " + toHex(rsaKeyPairPlus.getPrivate().getEncoded()));
        if (!Arrays.equals(rsaPrivJCE.getEncoded(), rsaKeyPairPlus.getPrivate().getEncoded())) {
            fail("RSA private key does not match generated private key");
        }

    }

    protected void keyFactoryCreateFromEncodedJCEToPlus(int size) throws Exception {

        KeyPair rsaKeyPairJCE = generateKeyPair(rsaKeyPairGenJCE, size);

        X509EncodedKeySpec x509SpecJCE = new X509EncodedKeySpec(
                rsaKeyPairJCE.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8SpecJCE = new PKCS8EncodedKeySpec(
                rsaKeyPairJCE.getPrivate().getEncoded());

        RSAPublicKey rsaPubJCE = (RSAPublicKey) rsaKeyFactoryJCE.generatePublic(x509SpecJCE);
        RSAPrivateKey rsaPrivJCE = (RSAPrivateKey) rsaKeyFactoryJCE.generatePrivate(pkcs8SpecJCE);



        if (!Arrays.equals(rsaPubJCE.getEncoded(), rsaKeyPairJCE.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }

        if (!Arrays.equals(rsaPrivJCE.getEncoded(), rsaKeyPairJCE.getPrivate().getEncoded())) {
            fail("RSA private key does not match generated public key");
        }



        //KeyPair rsaKeyPairInterOp = generateKeyPair(rsaKeyPairGenInterOp, size);

        //X509EncodedKeySpec  x509Spec = new X509EncodedKeySpec(rsaPubInterOp.getEncoded());
        //PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(rsaPrivInterOp.getEncoded());


        RSAPublicKey rsaPubPlus = (RSAPublicKey) rsaKeyFactoryPlus.generatePublic(x509SpecJCE);
        RSAPrivateKey rsaPrivPlus = (RSAPrivateKey) rsaKeyFactoryPlus.generatePrivate(pkcs8SpecJCE);
        if (!Arrays.equals(rsaPubPlus.getEncoded(), rsaKeyPairJCE.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }

        //System.out.println ("RSAPrivInterOp get Bytes " + toHex(rsaPrivPlus.getEncoded()));
        //System.out.println ("rsaKeyPairJCE.getPrivate().getEncoded() get Bytes " + toHex(rsaKeyPairJCE.getPrivate().getEncoded()));
        if (!Arrays.equals(rsaPrivPlus.getEncoded(), rsaKeyPairJCE.getPrivate().getEncoded())) {
            fail("RSA private key does not match generated private key");
        }

    }


    //--------------------------------------------------------------------------
    //
    //
    protected void keyFactoryCreateFromKeySpecJCEToPlus(int size) throws Exception {

        KeyPair rsaKeyPairJCE = generateKeyPair(rsaKeyPairGenJCE, size);

        RSAPublicKeySpec rsaPubSpecJCE = (RSAPublicKeySpec) rsaKeyFactoryJCE
                .getKeySpec(rsaKeyPairJCE.getPublic(), RSAPublicKeySpec.class);
        RSAPublicKey rsaPubJCE = (RSAPublicKey) rsaKeyFactoryJCE.generatePublic(rsaPubSpecJCE);

        if (!Arrays.equals(rsaPubJCE.getEncoded(), rsaKeyPairJCE.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }

        if (rsaKeyPairJCE.getPrivate() instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKeySpec rsaPrivateCrtSpecJCE = (RSAPrivateCrtKeySpec) rsaKeyFactoryJCE
                    .getKeySpec(rsaKeyPairJCE.getPrivate(), RSAPrivateCrtKeySpec.class);
            RSAPrivateCrtKey rsaPrivCrtJCE = (RSAPrivateCrtKey) rsaKeyFactoryJCE
                    .generatePrivate(rsaPrivateCrtSpecJCE);

            if (!Arrays.equals(rsaPrivCrtJCE.getEncoded(), rsaPrivCrtJCE.getEncoded())) {
                fail("RSA private CRT key does not match generated private key");
            }

            RSAPrivateKeySpec rsaPrivateSpecJCE = (RSAPrivateKeySpec) rsaKeyFactoryJCE
                    .getKeySpec(rsaPrivCrtJCE, RSAPrivateKeySpec.class);
            try {
                rsaKeyFactoryJCE.generatePrivate(rsaPrivateSpecJCE);
            } catch (InvalidKeySpecException ikse) {
                assertTrue("JCEPlus InvalidKeySpeccException = " + ikse.getMessage(), false);
            }
        } else {
            RSAPrivateKeySpec rsaPrivateSpecJCE = (RSAPrivateKeySpec) rsaKeyFactoryJCE
                    .getKeySpec(rsaKeyPairJCE.getPrivate(), RSAPrivateKeySpec.class);
            RSAPrivateKey rsaPrivJCE = (RSAPrivateKey) rsaKeyFactoryJCE
                    .generatePrivate(rsaPrivateSpecJCE);

            if (!Arrays.equals(rsaPrivJCE.getEncoded(), rsaKeyPairJCE.getPrivate().getEncoded())) {
                fail("RSA private key does not match generated private key");
            }
        }
    }

    protected void keyFactoryCreateFromKeySpecPlusToJCE(int size) throws Exception {

        KeyPair rsaKeyPairPlus = generateKeyPair(rsaKeyPairGenPlus, size);

        RSAPublicKeySpec rsaPubSpecPlus = (RSAPublicKeySpec) rsaKeyFactoryPlus
                .getKeySpec(rsaKeyPairPlus.getPublic(), RSAPublicKeySpec.class);
        RSAPublicKey rsaPubPlus = (RSAPublicKey) rsaKeyFactoryPlus.generatePublic(rsaPubSpecPlus);

        if (!Arrays.equals(rsaPubPlus.getEncoded(), rsaKeyPairPlus.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }

        if (rsaKeyPairPlus.getPrivate() instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKeySpec rsaPrivateCrtSpecPlus = (RSAPrivateCrtKeySpec) rsaKeyFactoryPlus
                    .getKeySpec(rsaKeyPairPlus.getPrivate(), RSAPrivateCrtKeySpec.class);
            RSAPrivateCrtKey rsaPrivCrtPlus = (RSAPrivateCrtKey) rsaKeyFactoryPlus
                    .generatePrivate(rsaPrivateCrtSpecPlus);

            if (!Arrays.equals(rsaPrivCrtPlus.getEncoded(),
                    rsaKeyPairPlus.getPrivate().getEncoded())) {
                fail("RSA private CRT key does not match generated private key");
            }

            RSAPrivateKeySpec rsaPrivateSpecPlus = (RSAPrivateKeySpec) rsaKeyFactoryPlus
                    .getKeySpec(rsaKeyPairPlus.getPrivate(), RSAPrivateKeySpec.class);
            try {

                rsaKeyFactoryPlus.generatePrivate(rsaPrivateSpecPlus);
            } catch (InvalidKeySpecException ikse) {

                assertTrue("JCEPlus InvalidKeySpeccException = " + ikse.getMessage(), false);
            }
        } else {
            RSAPrivateKeySpec rsaPrivateSpecPlus = (RSAPrivateKeySpec) rsaKeyFactoryPlus
                    .getKeySpec(rsaKeyPairPlus.getPrivate(), RSAPrivateKeySpec.class);
            RSAPrivateKey rsaPrivPlus = (RSAPrivateKey) rsaKeyFactoryPlus
                    .generatePrivate(rsaPrivateSpecPlus);

            if (!Arrays.equals(rsaPrivPlus.getEncoded(),
                    rsaKeyPairPlus.getPrivate().getEncoded())) {
                fail("RSA private key does not match generated private key");
            }
        }
    }

    public void testSignJCEAndVerifyPlus() {
        try {

            rsaKeyPairGenJCE.initialize(this.keySize);
            KeyPair rsaKeyPairJCE = rsaKeyPairGenJCE.generateKeyPair();

            rsaKeyPairJCE.getPublic();
            RSAPrivateKey rsaPrivJCE = (RSAPrivateKey) rsaKeyPairJCE.getPrivate();
            Signature signingJCE = Signature.getInstance("SHA256WithRSA", interopProviderName);
            signingJCE.initSign(rsaPrivJCE);
            signingJCE.update(origMsg);
            byte[] signedBytesJCE = signingJCE.sign();

            X509EncodedKeySpec x509SpecJCE = new X509EncodedKeySpec(
                    rsaKeyPairJCE.getPublic().getEncoded());
            PKCS8EncodedKeySpec pkcs8SpecJCE = new PKCS8EncodedKeySpec(
                    rsaKeyPairJCE.getPrivate().getEncoded());

            RSAPublicKey rsaPubPlus = (RSAPublicKey) rsaKeyFactoryPlus.generatePublic(x509SpecJCE);
            rsaKeyFactoryPlus.generatePrivate(pkcs8SpecJCE);

            Signature verifyingPlus = Signature.getInstance("SHA256withRSA", providerName);
            verifyingPlus.initVerify(rsaPubPlus);
            verifyingPlus.update(origMsg);
            assertTrue("Signature verification failed", verifyingPlus.verify(signedBytesJCE));
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue("signJCEAndVerifyPlus failed", false);
        }
    }

    public void testSignJCEAndVerifyPlusPrivateCrt() {

        try {

            rsaKeyPairGenJCE.initialize(this.keySize);
            KeyPair rsaKeyPairJCE = rsaKeyPairGenJCE.generateKeyPair();

            rsaKeyPairJCE.getPublic();
            RSAPrivateCrtKey rsaPrivJCE = (RSAPrivateCrtKey) rsaKeyPairJCE.getPrivate();
            Signature signingJCE = Signature.getInstance("SHA256WithRSA", interopProviderName);
            signingJCE.initSign(rsaPrivJCE);
            signingJCE.update(origMsg);
            byte[] signedBytesJCE = signingJCE.sign();

            X509EncodedKeySpec x509SpecJCE = new X509EncodedKeySpec(
                    rsaKeyPairJCE.getPublic().getEncoded());
            PKCS8EncodedKeySpec pkcs8SpecJCE = new PKCS8EncodedKeySpec(
                    rsaKeyPairJCE.getPrivate().getEncoded());

            RSAPublicKey rsaPubPlus = (RSAPublicKey) rsaKeyFactoryPlus.generatePublic(x509SpecJCE);
            rsaKeyFactoryPlus.generatePrivate(pkcs8SpecJCE);

            Signature verifyingPlus = Signature.getInstance("SHA256withRSA", providerName);
            verifyingPlus.initVerify(rsaPubPlus);
            verifyingPlus.update(origMsg);
            assertTrue("Signature verification failed", verifyingPlus.verify(signedBytesJCE));
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue("signJCEAndVerifyPlus failed", false);
        }
    }

    public void testSignPlusAndVerifyJCE() {

        try {
            rsaKeyPairGenPlus.initialize(this.keySize);
            KeyPair rsaKeyPairPlus = rsaKeyPairGenPlus.generateKeyPair();

            rsaKeyPairPlus.getPublic();
            RSAPrivateKey rsaPrivPlus = (RSAPrivateKey) rsaKeyPairPlus.getPrivate();
            Signature signingPlus = Signature.getInstance("SHA256WithRSA", providerName);
            signingPlus.initSign(rsaPrivPlus);
            signingPlus.update(origMsg);
            byte[] signedBytesPlus = signingPlus.sign();

            X509EncodedKeySpec x509SpecPlus = new X509EncodedKeySpec(
                    rsaKeyPairPlus.getPublic().getEncoded());
            PKCS8EncodedKeySpec pkcs8SpecPlus = new PKCS8EncodedKeySpec(
                    rsaKeyPairPlus.getPrivate().getEncoded());

            RSAPublicKey rsaPubJCE = (RSAPublicKey) rsaKeyFactoryJCE.generatePublic(x509SpecPlus);
            rsaKeyFactoryJCE.generatePrivate(pkcs8SpecPlus);

            Signature verifyingJCE = Signature.getInstance("SHA256withRSA", interopProviderName);
            verifyingJCE.initVerify(rsaPubJCE);
            verifyingJCE.update(origMsg);
            assertTrue("Signature verification", verifyingJCE.verify(signedBytesPlus));
        }

        catch (Exception ex) {
            ex.printStackTrace();
            assertTrue("SignAndVerify failed", false);
        }


    }


    public void testSignPlusAndVerifyJCECrt() {
        try {

            rsaKeyPairGenPlus.initialize(this.keySize);
            KeyPair rsaKeyPairPlus = rsaKeyPairGenPlus.generateKeyPair();

            rsaKeyPairPlus.getPublic();
            RSAPrivateCrtKey rsaPrivPlus = (RSAPrivateCrtKey) rsaKeyPairPlus.getPrivate();
            Signature signingPlus = Signature.getInstance("SHA256WithRSA", providerName);
            signingPlus.initSign(rsaPrivPlus);
            signingPlus.update(origMsg);
            byte[] signedBytesPlus = signingPlus.sign();

            X509EncodedKeySpec x509SpecPlus = new X509EncodedKeySpec(
                    rsaKeyPairPlus.getPublic().getEncoded());
            PKCS8EncodedKeySpec pkcs8SpecPlus = new PKCS8EncodedKeySpec(
                    rsaKeyPairPlus.getPrivate().getEncoded());

            RSAPublicKey rsaPubJCE = (RSAPublicKey) rsaKeyFactoryJCE.generatePublic(x509SpecPlus);
            rsaKeyFactoryJCE.generatePrivate(pkcs8SpecPlus);

            Signature verifyingJCE = Signature.getInstance("SHA256withRSA", providerName);
            verifyingJCE.initVerify(rsaPubJCE);
            verifyingJCE.update(origMsg);
            assertTrue("Signature verification failed", verifyingJCE.verify(signedBytesPlus));
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue("signPlusAndVerifyJCE failed", false);
        }
    }

    public void testEncryptPlusDecryptJCE() {

        try {


            byte[] msgBytes = ("This is a short msg".getBytes());
            //            public and Private key;" + 
            //                "encrypt with JCE and d/ecrypt with JCEPlus and vice versa").getBytes();
            byte[] cipherText;
            rsaKeyPairGenPlus.initialize(this.keySize);
            KeyPair rsaKeyPairPlus = rsaKeyPairGenPlus.generateKeyPair();

            RSAPublicKey rsaPubPlus = (RSAPublicKey) rsaKeyPairPlus.getPublic();
            rsaKeyPairPlus.getPrivate();
            Cipher cipherPlus = null;
            try {
                cipherPlus = Cipher.getInstance("RSA/ECB/PKCS1Padding", providerName);
            } catch (NoSuchAlgorithmException nsae) {
                if (providerName.equals("OpenJCEPlusFIPS")) {
                    assertEquals("No such algorithm: RSA/ECB/PKCS1Padding", nsae.getMessage());
                    return;
                } else {
                    throw nsae;
                }
            }
            cipherPlus.init(Cipher.ENCRYPT_MODE, rsaPubPlus);
            cipherText = cipherPlus.doFinal(msgBytes);

            X509EncodedKeySpec x509SpecPlus = new X509EncodedKeySpec(
                    rsaKeyPairPlus.getPublic().getEncoded());
            PKCS8EncodedKeySpec pkcs8SpecPlus = new PKCS8EncodedKeySpec(
                    rsaKeyPairPlus.getPrivate().getEncoded());

            rsaKeyFactoryJCE.generatePublic(x509SpecPlus);
            RSAPrivateCrtKey rsaPrivJCE = (RSAPrivateCrtKey) rsaKeyFactoryJCE
                    .generatePrivate(pkcs8SpecPlus);

            Cipher cipherJCE = null;
            try {
                cipherJCE = Cipher.getInstance("RSA/ECB/PKCS1Padding", providerName);
            } catch (NoSuchAlgorithmException nsae) {
                if (providerName.equals("OpenJCEPlusFIPS")) {
                    assertEquals("No such algorithm: RSA/ECB/PKCS1Padding", nsae.getMessage());
                    return;
                } else {
                    throw nsae;
                }
            }
            cipherJCE.init(Cipher.DECRYPT_MODE, rsaPrivJCE);
            byte[] decryptedBytes = cipherJCE.doFinal(cipherText);
            System.out.println("msgBytes = " + toHex(msgBytes));
            System.out.println("decryptedBytes = " + toHex(decryptedBytes));
            assertTrue(Arrays.equals(msgBytes, decryptedBytes));
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue("testEncryptPlusDecryptJCE", false);
        }
    }

    public void testEncryptJCEDecryptPlus() {
        byte[] msgBytes = ("This is a short message".getBytes());
        //long message to be encrypted and decrypted using RSA public and Private key;" + 
        //        "encrypt with JCE and decrypt with JCEPlus and vice versa").getBytes();

        try {
            byte[] cipherText = null;
            rsaKeyPairGenJCE.initialize(this.keySize);
            KeyPair rsaKeyPairJCE = rsaKeyPairGenJCE.generateKeyPair();

            RSAPublicKey rsaPubJCE = (RSAPublicKey) rsaKeyPairJCE.getPublic();
            rsaKeyPairJCE.getPrivate();
            Cipher cipherJCE = null;
            try {
                cipherJCE = Cipher.getInstance("RSA/ECB/PKCS1Padding", providerName);
            } catch (NoSuchAlgorithmException nsae) {
                if (providerName.equals("OpenJCEPlusFIPS")) {
                    assertEquals("No such algorithm: RSA/ECB/PKCS1Padding", nsae.getMessage());
                    return;
                } else {
                    throw nsae;
                }
            }
            
            cipherJCE.init(Cipher.ENCRYPT_MODE, rsaPubJCE);
            cipherText = cipherJCE.doFinal(msgBytes);

            X509EncodedKeySpec x509SpecJCE = new X509EncodedKeySpec(
                    rsaKeyPairJCE.getPublic().getEncoded());
            PKCS8EncodedKeySpec pkcs8SpecJCE = new PKCS8EncodedKeySpec(
                    rsaKeyPairJCE.getPrivate().getEncoded());

            rsaKeyFactoryPlus.generatePublic(x509SpecJCE);
            RSAPrivateCrtKey rsaPrivPlus = (RSAPrivateCrtKey) rsaKeyFactoryPlus
                    .generatePrivate(pkcs8SpecJCE);

            Cipher cipherPlus = null;
            try {
                cipherPlus = Cipher.getInstance("RSA/ECB/PKCS1Padding", providerName);
            } catch (NoSuchAlgorithmException nsae) {
                if (providerName.equals("OpenJCEPlusFIPS")) {
                    assertEquals("No such algorithm: RSA/ECB/PKCS1Padding", nsae.getMessage());
                    return;
                } else {
                    throw nsae;
                }
            }

            cipherPlus.init(Cipher.DECRYPT_MODE, rsaPrivPlus);
            byte[] decryptedBytes = cipherPlus.doFinal(cipherText);
            System.out.println("msgBytes = " + toHex(msgBytes));
            System.out.println("decryptedBytes = " + toHex(decryptedBytes));
            assertTrue(Arrays.equals(msgBytes, decryptedBytes));
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(" testEncryptJCEDecryptPlus", false);
        }
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

