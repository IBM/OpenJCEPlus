/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestRSAKeyInteropBC extends BaseTestJunit5Interop {


    protected KeyPairGenerator rsaKeyPairGenPlus;
    protected KeyFactory rsaKeyFactoryPlus;
    protected KeyPairGenerator rsaKeyPairGenBC;
    protected KeyFactory rsaKeyFactoryBC;

    byte[] origMsg = "this is the original message to be signed".getBytes();

    @BeforeEach
    public void setUp() throws Exception {
        rsaKeyPairGenPlus = KeyPairGenerator.getInstance("RSA", getProviderName());
        rsaKeyFactoryPlus = KeyFactory.getInstance("RSA", getProviderName());
        rsaKeyPairGenBC = KeyPairGenerator.getInstance("RSA", getInteropProviderName());
        rsaKeyFactoryBC = KeyFactory.getInstance("RSA", getInteropProviderName());
    }

    @Test
    public void testRSAKeyGen_PlusToBC() throws Exception {
        int keySize = 1024;
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            keySize = 2048;
        }
        KeyPair rsaKeyPairPlus = generateKeyPair(rsaKeyPairGenPlus, keySize);
        RSAPublicKey publicKeyPlus = (RSAPublicKey) rsaKeyPairPlus.getPublic();
        RSAPrivateKey privateKeyPlus = (RSAPrivateKey) rsaKeyPairPlus.getPrivate();
        byte[] publicKeyBytesPlus = publicKeyPlus.getEncoded();
        byte[] privateKeyBytesPlus = privateKeyPlus.getEncoded();

        //KeyFactory keyFactory = KeyFactory.getInstance("RSA", interopProviderName);
        EncodedKeySpec privateKeySpecPlus = new PKCS8EncodedKeySpec(privateKeyBytesPlus);
        EncodedKeySpec publicKeySpecPlus = new X509EncodedKeySpec(publicKeyBytesPlus);
        PublicKey publicKeyBC = rsaKeyFactoryBC.generatePublic(publicKeySpecPlus);
        PrivateKey privateKeyBC = rsaKeyFactoryBC.generatePrivate(privateKeySpecPlus);


        // The original and new keys are the same
        //boolean same = privateKeyPlus.equals(privateKeyBC);
        boolean same = Arrays.equals(privateKeyBytesPlus, privateKeyBC.getEncoded());
        assertTrue(same);
        same = Arrays.equals(publicKeyBytesPlus, publicKeyBC.getEncoded());
        assertTrue(same);

    }

    @Test
    public void testRSAKeyGen_BCToPlus() throws Exception {
        int keySize = 1024;
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            keySize = 2048;
        }
        KeyPair rsaKeyPairBC = generateKeyPair(rsaKeyPairGenBC, keySize);
        RSAPublicKey publicKeyBC = (RSAPublicKey) rsaKeyPairBC.getPublic();
        RSAPrivateKey privateKeyBC = (RSAPrivateKey) rsaKeyPairBC.getPrivate();
        byte[] publicKeyBytesBC = publicKeyBC.getEncoded();
        byte[] privateKeyBytesBC = privateKeyBC.getEncoded();

        //KeyFactory keyFactory = KeyFactory.getInstance("RSA", interopProviderName);
        EncodedKeySpec privateKeySpecBC = new PKCS8EncodedKeySpec(privateKeyBytesBC);
        PrivateKey privateKeyPlus = rsaKeyFactoryPlus.generatePrivate(privateKeySpecBC);

        EncodedKeySpec publicKeySpecBC = new X509EncodedKeySpec(publicKeyBytesBC);
        PublicKey publicKeyPlus = rsaKeyFactoryPlus.generatePublic(publicKeySpecBC);

        // The original and new keys are the same
        boolean same = Arrays.equals(privateKeyBytesBC, privateKeyPlus.getEncoded());
        assertTrue(same);
        same = Arrays.equals(publicKeyBytesBC, publicKeyPlus.getEncoded());
        assertTrue(same);

    }

    @Test
    public void testRSAKeyFactoryCreateFromEncodedBCtoPlus_1024() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            return;
        }
        keyFactoryCreateFromEncodedBCToPlus(1024);
    }

    @Test
    public void testRSAKeyFactoryCreateFromEncodedPlusToBC_1024() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            return;
        }
        keyFactoryCreateFromEncodedPlusToBC(1024);
    }

    @Test
    public void testRSAKeyFactoryCreateFromKeySpecBCToPlus_2048() throws Exception {
        keyFactoryCreateFromKeySpecBCToPlus(2048);
    }

    @Test
    public void testRSAKeyFactoryCreateFromKeySpecPlusToBC_2048() throws Exception {
        keyFactoryCreateFromKeySpecPlusToBC(2048);
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


    protected void keyFactoryCreateFromEncodedPlusToBC(int size) throws Exception {

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

        //Test Interop  with BC

        RSAPublicKey rsaPubBC = (RSAPublicKey) rsaKeyFactoryBC.generatePublic(x509SpecPlus);
        RSAPrivateKey rsaPrivBC = (RSAPrivateKey) rsaKeyFactoryBC.generatePrivate(pkcs8SpecPlus);
        if (!Arrays.equals(rsaPubBC.getEncoded(), rsaKeyPairPlus.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }

        //System.out.println ("RSAPrivInterOp get Bytes " + toHex(rsaPrivBC.getEncoded()));
        //System.out.println ("rsaKeyPair.getPrivate().getEncoded() get Bytes " + toHex(rsaKeyPairPlus.getPrivate().getEncoded()));
        if (!Arrays.equals(rsaPrivBC.getEncoded(), rsaKeyPairPlus.getPrivate().getEncoded())) {
            fail("RSA private key does not match generated private key");
        }

    }

    protected void keyFactoryCreateFromEncodedBCToPlus(int size) throws Exception {

        KeyPair rsaKeyPairBC = generateKeyPair(rsaKeyPairGenBC, size);

        X509EncodedKeySpec x509SpecBC = new X509EncodedKeySpec(
                rsaKeyPairBC.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8SpecBC = new PKCS8EncodedKeySpec(
                rsaKeyPairBC.getPrivate().getEncoded());

        RSAPublicKey rsaPubBC = (RSAPublicKey) rsaKeyFactoryBC.generatePublic(x509SpecBC);
        RSAPrivateKey rsaPrivBC = (RSAPrivateKey) rsaKeyFactoryBC.generatePrivate(pkcs8SpecBC);



        if (!Arrays.equals(rsaPubBC.getEncoded(), rsaKeyPairBC.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }

        if (!Arrays.equals(rsaPrivBC.getEncoded(), rsaKeyPairBC.getPrivate().getEncoded())) {
            fail("RSA private key does not match generated public key");
        }



        //KeyPair rsaKeyPairInterOp = generateKeyPair(rsaKeyPairGenInterOp, size);

        //X509EncodedKeySpec  x509Spec = new X509EncodedKeySpec(rsaPubInterOp.getEncoded());
        //PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(rsaPrivInterOp.getEncoded());


        RSAPublicKey rsaPubPlus = (RSAPublicKey) rsaKeyFactoryPlus.generatePublic(x509SpecBC);
        RSAPrivateKey rsaPrivPlus = (RSAPrivateKey) rsaKeyFactoryPlus.generatePrivate(pkcs8SpecBC);
        if (!Arrays.equals(rsaPubPlus.getEncoded(), rsaKeyPairBC.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }

        //System.out.println ("RSAPrivInterOp get Bytes " + toHex(rsaPrivPlus.getEncoded()));
        //System.out.println ("rsaKeyPairBC.getPrivate().getEncoded() get Bytes " + toHex(rsaKeyPairBC.getPrivate().getEncoded()));
        if (!Arrays.equals(rsaPrivPlus.getEncoded(), rsaKeyPairBC.getPrivate().getEncoded())) {
            fail("RSA private key does not match generated private key");
        }

    }



    protected void keyFactoryCreateFromKeySpecBCToPlus(int size) throws Exception {

        KeyPair rsaKeyPairBC = generateKeyPair(rsaKeyPairGenBC, size);

        RSAPublicKeySpec rsaPubSpecBC = rsaKeyFactoryBC
                .getKeySpec(rsaKeyPairBC.getPublic(), RSAPublicKeySpec.class);
        RSAPublicKey rsaPubBC = (RSAPublicKey) rsaKeyFactoryBC.generatePublic(rsaPubSpecBC);

        if (!Arrays.equals(rsaPubBC.getEncoded(), rsaKeyPairBC.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }

        if (rsaKeyPairBC.getPrivate() instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKeySpec rsaPrivateCrtSpecBC = rsaKeyFactoryBC
                    .getKeySpec(rsaKeyPairBC.getPrivate(), RSAPrivateCrtKeySpec.class);
            RSAPrivateCrtKey rsaPrivCrtBC = (RSAPrivateCrtKey) rsaKeyFactoryBC
                    .generatePrivate(rsaPrivateCrtSpecBC);

            if (!Arrays.equals(rsaPrivCrtBC.getEncoded(), rsaPrivCrtBC.getEncoded())) {
                fail("RSA private CRT key does not match generated private key");
            }

            RSAPrivateKeySpec rsaPrivateSpecBC = rsaKeyFactoryBC
                    .getKeySpec(rsaPrivCrtBC, RSAPrivateKeySpec.class);
            try {
                rsaKeyFactoryBC.generatePrivate(rsaPrivateSpecBC);
            } catch (InvalidKeySpecException ikse) {
                assertTrue(false, "BCPlus InvalidKeySpeccException = " + ikse.getMessage());
            }
        } else {
            RSAPrivateKeySpec rsaPrivateSpecBC = rsaKeyFactoryBC
                    .getKeySpec(rsaKeyPairBC.getPrivate(), RSAPrivateKeySpec.class);
            RSAPrivateKey rsaPrivBC = (RSAPrivateKey) rsaKeyFactoryBC
                    .generatePrivate(rsaPrivateSpecBC);

            if (!Arrays.equals(rsaPrivBC.getEncoded(), rsaKeyPairBC.getPrivate().getEncoded())) {
                fail("RSA private key does not match generated private key");
            }
        }
    }

    protected void keyFactoryCreateFromKeySpecPlusToBC(int size) throws Exception {

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

                assertTrue(false, "BCPlus InvalidKeySpeccException = " + ikse.getMessage());
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
    public void testSignBCAndVerifyPlus() {
        try {

            int keySize = 1024;
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                keySize = 2048;
            }
            rsaKeyPairGenBC.initialize(keySize);
            KeyPair rsaKeyPairBC = rsaKeyPairGenBC.generateKeyPair();

            rsaKeyPairBC.getPublic();
            RSAPrivateKey rsaPrivBC = (RSAPrivateKey) rsaKeyPairBC.getPrivate();
            Signature signingBC = Signature.getInstance("SHA256WithRSA", getInteropProviderName());
            signingBC.initSign(rsaPrivBC);
            signingBC.update(origMsg);
            byte[] signedBytesBC = signingBC.sign();

            X509EncodedKeySpec x509SpecBC = new X509EncodedKeySpec(
                    rsaKeyPairBC.getPublic().getEncoded());
            PKCS8EncodedKeySpec pkcs8SpecBC = new PKCS8EncodedKeySpec(
                    rsaKeyPairBC.getPrivate().getEncoded());

            RSAPublicKey rsaPubPlus = (RSAPublicKey) rsaKeyFactoryPlus.generatePublic(x509SpecBC);
            rsaKeyFactoryPlus.generatePrivate(pkcs8SpecBC);

            Signature verifyingPlus = Signature.getInstance("SHA256withRSA", getProviderName());
            verifyingPlus.initVerify(rsaPubPlus);
            verifyingPlus.update(origMsg);
            assertTrue(verifyingPlus.verify(signedBytesBC), "Signature verification failed");
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "signBCAndVerifyPlus failed");
        }
    }

    @Test
    public void testSignBCAndVerifyPlusPrivateCrt() {

        try {

            int keySize = 1024;
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                keySize = 2048;
            }
            rsaKeyPairGenBC.initialize(keySize);
            KeyPair rsaKeyPairBC = rsaKeyPairGenBC.generateKeyPair();

            rsaKeyPairBC.getPublic();
            RSAPrivateCrtKey rsaPrivBC = (RSAPrivateCrtKey) rsaKeyPairBC.getPrivate();
            Signature signingBC = Signature.getInstance("SHA256WithRSA", getInteropProviderName());
            signingBC.initSign(rsaPrivBC);
            signingBC.update(origMsg);
            byte[] signedBytesBC = signingBC.sign();

            X509EncodedKeySpec x509SpecBC = new X509EncodedKeySpec(
                    rsaKeyPairBC.getPublic().getEncoded());
            PKCS8EncodedKeySpec pkcs8SpecBC = new PKCS8EncodedKeySpec(
                    rsaKeyPairBC.getPrivate().getEncoded());

            RSAPublicKey rsaPubPlus = (RSAPublicKey) rsaKeyFactoryPlus.generatePublic(x509SpecBC);
            rsaKeyFactoryPlus.generatePrivate(pkcs8SpecBC);

            Signature verifyingPlus = Signature.getInstance("SHA256withRSA", getProviderName());
            verifyingPlus.initVerify(rsaPubPlus);
            verifyingPlus.update(origMsg);
            assertTrue(verifyingPlus.verify(signedBytesBC), "Signature verification failed");
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "signBCAndVerifyPlus failed");
        }
    }

    @Test
    public void testSignPlusAndVerifyBC() {

        try {
            int keySize = 1024;
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                keySize = 2048;
            }
            rsaKeyPairGenPlus.initialize(keySize);
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

            RSAPublicKey rsaPubBC = (RSAPublicKey) rsaKeyFactoryBC.generatePublic(x509SpecPlus);
            rsaKeyFactoryBC.generatePrivate(pkcs8SpecPlus);

            Signature verifyingBC = Signature.getInstance("SHA256withRSA", getInteropProviderName());
            verifyingBC.initVerify(rsaPubBC);
            verifyingBC.update(origMsg);
            assertTrue(verifyingBC.verify(signedBytesPlus), "Signature verification");
        }

        catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "SignAndVerify failed");
        }


    }

    @Test
    public void testSignPlusAndVerifyBCCrt() {
        try {

            int keySize = 1024;
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                keySize = 2048;
            }
            rsaKeyPairGenPlus.initialize(keySize);
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

            RSAPublicKey rsaPubBC = (RSAPublicKey) rsaKeyFactoryBC.generatePublic(x509SpecPlus);
            rsaKeyFactoryBC.generatePrivate(pkcs8SpecPlus);

            Signature verifyingBC = Signature.getInstance("SHA256withRSA", getProviderName());
            verifyingBC.initVerify(rsaPubBC);
            verifyingBC.update(origMsg);
            assertTrue(verifyingBC.verify(signedBytesPlus), "Signature verification failed");
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "signPlusAndVerifyBC failed");
        }
    }

    @Test
    public void testEncryptPlusDecryptBC() {

        try {


            byte[] msgBytes = ("This is a short msg".getBytes());
            //            public and Private key;" + 
            //                "encrypt with BC and d/ecrypt with BCPlus and vice versa").getBytes();
            byte[] cipherText;
            int keySize = 1024;
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                keySize = 2048;
            }
            rsaKeyPairGenPlus.initialize(keySize);
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

            rsaKeyFactoryBC.generatePublic(x509SpecPlus);
            RSAPrivateCrtKey rsaPrivBC = (RSAPrivateCrtKey) rsaKeyFactoryBC
                    .generatePrivate(pkcs8SpecPlus);

            Cipher cipherBC = Cipher.getInstance("RSA/ECB/PKCS1Padding", getProviderName());
            cipherBC.init(Cipher.DECRYPT_MODE, rsaPrivBC);
            byte[] decryptedBytes = cipherBC.doFinal(cipherText);
            System.out.println("msgBytes = " + toHex(msgBytes));
            System.out.println("decryptedBytes = " + toHex(decryptedBytes));
            assertTrue(Arrays.equals(msgBytes, decryptedBytes));
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "testEncryptPlusDecryptBC");
        }
    }

    @Test
    public void testEncryptBCDecryptPlus() {
        byte[] msgBytes = ("This is a short message".getBytes());
        //long message to be encrypted and decrypted using RSA public and Private key;" + 
        //        "encrypt with BC and decrypt with BCPlus and vice versa").getBytes();

        try {
            byte[] cipherText;
            int keySize = 1024;
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                keySize = 2048;
            }
            rsaKeyPairGenBC.initialize(keySize);
            KeyPair rsaKeyPairBC = rsaKeyPairGenBC.generateKeyPair();

            RSAPublicKey rsaPubBC = (RSAPublicKey) rsaKeyPairBC.getPublic();
            rsaKeyPairBC.getPrivate();
            Cipher cipherBC = Cipher.getInstance("RSA/ECB/PKCS1Padding", getProviderName());
            cipherBC.init(Cipher.ENCRYPT_MODE, rsaPubBC);
            cipherText = cipherBC.doFinal(msgBytes);

            X509EncodedKeySpec x509SpecBC = new X509EncodedKeySpec(
                    rsaKeyPairBC.getPublic().getEncoded());
            PKCS8EncodedKeySpec pkcs8SpecBC = new PKCS8EncodedKeySpec(
                    rsaKeyPairBC.getPrivate().getEncoded());

            rsaKeyFactoryPlus.generatePublic(x509SpecBC);
            RSAPrivateCrtKey rsaPrivPlus = (RSAPrivateCrtKey) rsaKeyFactoryPlus
                    .generatePrivate(pkcs8SpecBC);

            Cipher cipherPlus = Cipher.getInstance("RSA/ECB/PKCS1Padding", getProviderName());
            cipherPlus.init(Cipher.DECRYPT_MODE, rsaPrivPlus);
            byte[] decryptedBytes = cipherPlus.doFinal(cipherText);
            System.out.println("msgBytes = " + toHex(msgBytes));
            System.out.println("decryptedBytes = " + toHex(decryptedBytes));
            assertTrue(Arrays.equals(msgBytes, decryptedBytes));
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, " testEncryptBCDecryptPlus");
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

