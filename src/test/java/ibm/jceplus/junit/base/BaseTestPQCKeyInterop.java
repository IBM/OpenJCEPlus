/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import ibm.jceplus.junit.openjceplus.Utils;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestPQCKeyInterop extends BaseTestJunit5Interop {


    protected KeyPairGenerator keyPairGenPlus;
    protected KeyFactory keyFactoryPlus;
    protected KeyPairGenerator keyPairGenInterop;
    protected KeyFactory keyFactoryInterop;

    byte[] origMsg = "this is the original message to be signed".getBytes();

    @Test
    public void testPQCKeyGenKEM_PlusToInterop() throws Exception {
        String pqcAlgorithm = "ML-KEM-512";
        boolean same;
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //This is not in the FIPS provider yet.
            return;
        }
        keyPairGenPlus = KeyPairGenerator.getInstance(pqcAlgorithm, getProviderName());
        keyFactoryPlus = KeyFactory.getInstance(pqcAlgorithm, getProviderName());
        keyPairGenInterop = KeyPairGenerator.getInstance(pqcAlgorithm, getInteropProviderName());
        keyFactoryInterop = KeyFactory.getInstance(pqcAlgorithm, getInteropProviderName());

        KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);
        PublicKey publicKeyPlus = keyPairPlus.getPublic();
        PrivateKey privateKeyPlus = keyPairPlus.getPrivate();
        byte[] publicKeyBytesPlus = publicKeyPlus.getEncoded();
        byte[] privateKeyBytesPlus = privateKeyPlus.getEncoded();

        PKCS8EncodedKeySpec privateKeySpecPlus = new PKCS8EncodedKeySpec(privateKeyBytesPlus);
        EncodedKeySpec publicKeySpecPlus = new X509EncodedKeySpec(publicKeyBytesPlus);
        PublicKey publicKeyInterop = keyFactoryInterop.generatePublic(publicKeySpecPlus);
        //Oracle currently has an extra Octet String for the Key. So Skip trying to create the private key
        if (!(getInteropProviderName().equals(Utils.PROVIDER_SunJCE))) {
            PrivateKey privateKeyInterop = keyFactoryInterop.generatePrivate(privateKeySpecPlus);
            same = Arrays.equals(privateKeyBytesPlus, privateKeyInterop.getEncoded());
            assertTrue(same);
        }

        // The original and new keys are the same
        same = Arrays.equals(publicKeyBytesPlus, publicKeyInterop.getEncoded());
        assertTrue(same);
    } 
    @Test
    public void testPQCKeyGenKEM_Interop() throws Exception {
        String pqcAlgorithm = "ML-KEM-512";
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //This is not in the FIPS provider yet.
            return;
        }
        keyPairGenPlus = KeyPairGenerator.getInstance(pqcAlgorithm, getProviderName());
        keyFactoryPlus = KeyFactory.getInstance(pqcAlgorithm, getProviderName());
        keyPairGenInterop = KeyPairGenerator.getInstance(pqcAlgorithm, getInteropProviderName());
        keyFactoryInterop = KeyFactory.getInstance(pqcAlgorithm, getInteropProviderName());

        KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);
        PublicKey publicKeyInterop = keyPairInterop.getPublic();
        PrivateKey privateKeyInterop = keyPairInterop.getPrivate();
        byte[] publicKeyBytesInterop = publicKeyInterop.getEncoded();
        byte[] privateKeyBytesInterop = privateKeyInterop.getEncoded();

        PKCS8EncodedKeySpec privateKeySpecInterop = new PKCS8EncodedKeySpec(privateKeyBytesInterop);
        EncodedKeySpec publicKeySpecInterop = new X509EncodedKeySpec(publicKeyBytesInterop);
        PublicKey publicKeyPlus = keyFactoryPlus.generatePublic(publicKeySpecInterop);
        PrivateKey privateKeyPlus = keyFactoryPlus.generatePrivate(privateKeySpecInterop);

        // The original and new keys are the same
        boolean same = Arrays.equals(privateKeyBytesInterop, privateKeyPlus.getEncoded());
        assertTrue(same);
        same = Arrays.equals(publicKeyBytesInterop, publicKeyPlus.getEncoded());
        assertTrue(same);

    }
    @Test
    public void testPQCKeyGenKEM_PlusToInteropRAW() throws Exception {
        String pqcAlgorithm = "ML-KEM-512";
        boolean same;
        if (getProviderName().equals("OpenJCEPlusFIPS") || 
            getInteropProviderName().equals(Utils.PROVIDER_BC)) {
            //This is not in the FIPS provider yet and Boucy Castle does not support this test.
            return;
        }
        keyPairGenPlus = KeyPairGenerator.getInstance(pqcAlgorithm, getProviderName());
        keyFactoryPlus = KeyFactory.getInstance(pqcAlgorithm, getProviderName());
        keyPairGenInterop = KeyPairGenerator.getInstance(pqcAlgorithm, getInteropProviderName());
        keyFactoryInterop = KeyFactory.getInstance(pqcAlgorithm, getInteropProviderName());

        KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);
        PublicKey publicKeyInterop = keyPairInterop.getPublic();
        PrivateKey privateKeyInterop = keyPairInterop.getPrivate();
        byte[] publicKeyBytesInterop = publicKeyInterop.getEncoded();
        byte[] privateKeyBytesInterop = privateKeyInterop.getEncoded();

        EncodedKeySpec eksInterop = keyFactoryInterop.getKeySpec(publicKeyInterop, EncodedKeySpec.class);
        PublicKey pub = keyFactoryPlus.generatePublic(eksInterop); 
        EncodedKeySpec eksPrivInterop = keyFactoryInterop.getKeySpec(privateKeyInterop, EncodedKeySpec.class);
        //Oracle currently has an extra Octet String for the Key. So Skip trying to create the private key
        if (!(getInteropProviderName().equals(Utils.PROVIDER_SunJCE))) {
            PrivateKey priv = keyFactoryPlus.generatePrivate(eksPrivInterop);
            same = Arrays.equals(privateKeyBytesInterop, priv.getEncoded());
            assertTrue(same);
        }
        
        // The original and new keys are the same
        same = Arrays.equals(publicKeyBytesInterop, pub.getEncoded());
        assertTrue(same);
    }
    @Test
    public void testPQCKeyGenMLDSA_PlusToInterop() throws Exception {
        String pqcAlgorithm = "ML-DSA-65";
        boolean same;
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //This is not in the FIPS provider yet.
            return;
        }
        keyPairGenPlus = KeyPairGenerator.getInstance(pqcAlgorithm, getProviderName());
        keyFactoryPlus = KeyFactory.getInstance(pqcAlgorithm, getProviderName());
        keyPairGenInterop = KeyPairGenerator.getInstance(pqcAlgorithm, getInteropProviderName2());
        keyFactoryInterop = KeyFactory.getInstance(pqcAlgorithm, getInteropProviderName2());

        KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);
        PublicKey publicKeyPlus = keyPairPlus.getPublic();
        //PrivateKey privateKeyPlus = keyPairPlus.getPrivate();
        byte[] publicKeyBytesPlus = publicKeyPlus.getEncoded();
        //byte[] privateKeyBytesPlus = privateKeyPlus.getEncoded();

        //PKCS8EncodedKeySpec privateKeySpecPlus = new PKCS8EncodedKeySpec(privateKeyBytesPlus);
        EncodedKeySpec publicKeySpecPlus = new X509EncodedKeySpec(publicKeyBytesPlus);
        PublicKey publicKeyInterop = keyFactoryInterop.generatePublic(publicKeySpecPlus);
        //Oracle currently has an extra Octet String for the Key. So Skip trying to create the private key
        //And BC is using a different encoding today for thier ML-DSA private keys.
        // So we can not compare these today.
        //PrivateKey privateKeyInterop = keyFactoryInterop.generatePrivate(privateKeySpecPlus);
        //same = Arrays.equals(privateKeyBytesPlus, privateKeyInterop.getEncoded());
        //assertTrue(same);
        

        // The original and new keys are the same
        same = Arrays.equals(publicKeyBytesPlus, publicKeyInterop.getEncoded());
        assertTrue(same);
    } 
    @Test
    public void testPQCKeyGenMLDSA_Interop() throws Exception {        
        String pqcAlgorithm = "ML-DSA-65";
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //This is not in the FIPS provider yet.
            return;
        }
        keyPairGenPlus = KeyPairGenerator.getInstance(pqcAlgorithm, getProviderName());
        keyFactoryPlus = KeyFactory.getInstance(pqcAlgorithm, getProviderName());
        keyPairGenInterop = KeyPairGenerator.getInstance(pqcAlgorithm, getInteropProviderName2());
        keyFactoryInterop = KeyFactory.getInstance(pqcAlgorithm, getInteropProviderName2());

        KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);
        PublicKey publicKeyInterop = keyPairInterop.getPublic();
        PrivateKey privateKeyInterop = keyPairInterop.getPrivate();
        byte[] publicKeyBytesInterop = publicKeyInterop.getEncoded();
        byte[] privateKeyBytesInterop = privateKeyInterop.getEncoded();

        PKCS8EncodedKeySpec privateKeySpecInterop = new PKCS8EncodedKeySpec(privateKeyBytesInterop);
        EncodedKeySpec publicKeySpecInterop = new X509EncodedKeySpec(publicKeyBytesInterop);
        PublicKey publicKeyPlus = keyFactoryPlus.generatePublic(publicKeySpecInterop);
        PrivateKey privateKeyPlus = keyFactoryPlus.generatePrivate(privateKeySpecInterop);

        // The original and new keys are the same
        boolean same = Arrays.equals(privateKeyBytesInterop, privateKeyPlus.getEncoded());
        assertTrue(same);
        same = Arrays.equals(publicKeyBytesInterop, publicKeyPlus.getEncoded());
        assertTrue(same);

    }
    @Test
    public void testPQCKeyGenMLDSA_PlusToInteropRAW() throws Exception {
        String pqcAlgorithm = "ML-DSA-65";
        boolean same;
        if (getProviderName().equals("OpenJCEPlusFIPS") || 
            getInteropProviderName().equals(Utils.PROVIDER_BC)) {
            //This is not in the FIPS provider yet and Bouncy Castle does not support this test.
            return;
        }
        keyPairGenPlus = KeyPairGenerator.getInstance(pqcAlgorithm, getProviderName());
        keyFactoryPlus = KeyFactory.getInstance(pqcAlgorithm, getProviderName());
        keyPairGenInterop = KeyPairGenerator.getInstance(pqcAlgorithm, getInteropProviderName2());
        keyFactoryInterop = KeyFactory.getInstance(pqcAlgorithm, getInteropProviderName2());

        KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);
        PublicKey publicKeyInterop = keyPairInterop.getPublic();
        //PrivateKey privateKeyInterop = keyPairInterop.getPrivate();
        byte[] publicKeyBytesInterop = publicKeyInterop.getEncoded();
        //byte[] privateKeyBytesInterop = privateKeyInterop.getEncoded();

        EncodedKeySpec eksInterop = keyFactoryInterop.getKeySpec(publicKeyInterop, EncodedKeySpec.class);
        PublicKey pub = keyFactoryPlus.generatePublic(eksInterop); 
        //EncodedKeySpec eksPrivInterop = keyFactoryInterop.getKeySpec(privateKeyInterop, EncodedKeySpec.class);
        
        //Oracle currently has an extra Octet String for the Key. So Skip trying to create the private key and test
        //PrivateKey priv = keyFactoryPlus.generatePrivate(eksPrivInterop);
        //same = Arrays.equals(privateKeyBytesInterop, priv.getEncoded());
        //assertTrue(same);
    
        
        // The original and new keys are the same
        same = Arrays.equals(publicKeyBytesInterop, pub.getEncoded());
        assertTrue(same);
    }

    protected KeyPair generateKeyPair(KeyPairGenerator keyPairGen) throws Exception {
        KeyPair keyPair = keyPairGen.generateKeyPair();

        if (keyPair.getPrivate() == null) {
            fail("Private key is null");
        }

        if (keyPair.getPublic() == null) {
            fail("Public key is null");
        }

        return keyPair;
    }
 
    @ParameterizedTest
    @CsvSource({"ML-DSA-44","ML-DSA-65","ML-DSA-87"})
    public void testSignInteropAndVerifyPlus(String algorithm) {
        try {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                //This is not in the FIPS provider yet.
                return;
            }
            keyPairGenInterop = KeyPairGenerator.getInstance(algorithm, getInteropProviderName2());
            KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);

            PublicKey publicKeyInterop = keyPairInterop.getPublic();
            PrivateKey privateKeyInterop = keyPairInterop.getPrivate();

            Signature signingInterop = Signature.getInstance(algorithm, getInteropProviderName2());
            signingInterop.initSign(privateKeyInterop);
            signingInterop.update(origMsg);
            byte[] signedBytesInterop = signingInterop.sign();

            X509EncodedKeySpec x509SpecInterop = new X509EncodedKeySpec(
                publicKeyInterop.getEncoded());

            KeyFactory keyFactoryPlus = KeyFactory.getInstance(algorithm, getProviderName());
            PublicKey pubPlus = keyFactoryPlus.generatePublic(x509SpecInterop);

            Signature verifyingPlus = Signature.getInstance(algorithm, getProviderName());
            verifyingPlus.initVerify(pubPlus);
            verifyingPlus.update(origMsg);
            assertTrue(verifyingPlus.verify(signedBytesInterop), "Signature verification failed");
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "SignInteropAndVerifyPlus failed");
        }
    }
    @ParameterizedTest
    @CsvSource({"ML-DSA-44","ML-DSA-65","ML-DSA-87"})
    public void testSignPlusAndVerifyInterop(String algorithm) {
        try {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                //This is not in the FIPS provider yet.
                return;
            }

            keyPairGenPlus = KeyPairGenerator.getInstance(algorithm, getProviderName());
            KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);

            PublicKey publicKeyPlus = keyPairPlus.getPublic();
            PrivateKey privateKeyPlus = keyPairPlus.getPrivate();

            Signature signingPlus = Signature.getInstance(algorithm, getProviderName());
            signingPlus.initSign(privateKeyPlus);
            signingPlus.update(origMsg);
            byte[] signedBytesPlus = signingPlus.sign();

            X509EncodedKeySpec x509SpecInterop = new X509EncodedKeySpec(
                publicKeyPlus.getEncoded());

            KeyFactory keyFactoryInterop = KeyFactory.getInstance(algorithm, getInteropProviderName2());
            PublicKey pubInterop = keyFactoryInterop.generatePublic(x509SpecInterop);

            Signature verifyingPlus = Signature.getInstance(algorithm, getInteropProviderName2());
            verifyingPlus.initVerify(pubInterop);
            verifyingPlus.update(origMsg);
            assertTrue(verifyingPlus.verify(signedBytesPlus), "Signature verification failed");
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "SignPlusAndVerifyInterop failed");
        }
    }
    
    @ParameterizedTest
    @CsvSource({"ML-KEM-512","ML-KEM-768","ML-KEM-1024"})
    public void testKEMPlusCreatesInteropGet(String Algorithm) {
        try {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                //This is not in the FIPS provider yet and Oracle Private keys have an extra Octet in them.
                return;
            }

            KEM kemPlus = KEM.getInstance(Algorithm, getProviderName());
            KEM kemInterop = KEM.getInstance("ML-KEM", getInteropProviderName());

            keyPairGenPlus = KeyPairGenerator.getInstance(Algorithm, getProviderName());
            KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);

            PublicKey publicKeyPlus = keyPairPlus.getPublic();
            PrivateKey privateKeyPlus = keyPairPlus.getPrivate();
            
            X509EncodedKeySpec publicKeySpecInterop = new X509EncodedKeySpec(publicKeyPlus.getEncoded());
            KeyFactory keyFactoryInterop = KeyFactory.getInstance(Algorithm, getInteropProviderName());
            PublicKey publicKeyInterop = keyFactoryInterop.generatePublic(publicKeySpecInterop);

            KEM.Encapsulator encr = kemInterop.newEncapsulator(publicKeyInterop);
            KEM.Encapsulated enc = encr.encapsulate(0,32,"AES");
            if (enc == null){
                System.out.println("enc = null");
                assertTrue(false, "KEMPlusCreatesInteropGet failed no enc.");
            }
            SecretKey keyE = enc.key();
           
            KEM.Decapsulator decr = kemPlus.newDecapsulator(privateKeyPlus);
            SecretKey keyD = decr.decapsulate(enc.encapsulation(),0,32,"AES");

            assertTrue(Arrays.equals(keyE.getEncoded(), keyD.getEncoded()), "Secrets do NOT match");
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "KEMPlusCreatesInteropGet failed");
        }
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM-512","ML-KEM-768","ML-KEM-1024"})
    public void testKEMInteropCreatesPlusGet(String Algorithm) {
        try {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                //This is not in the FIPS provider yet and Oracle Private keys have an extra Octet in them.
                return;
            }

            KEM kemPlus = KEM.getInstance(Algorithm, getProviderName());
            KEM kemInterop = KEM.getInstance("ML-KEM", getInteropProviderName());

            keyPairGenInterop = KeyPairGenerator.getInstance(Algorithm, getInteropProviderName());
            KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);
            PublicKey publicKeyInterop = keyPairInterop.getPublic();
            PrivateKey privateKeyInterop = keyPairInterop.getPrivate();

            X509EncodedKeySpec publicKeySpecInterop = new X509EncodedKeySpec(publicKeyInterop.getEncoded());

            KeyFactory keyFactoryPlus = KeyFactory.getInstance(Algorithm, getProviderName());
            PublicKey publicKeyPlus = keyFactoryPlus.generatePublic(publicKeySpecInterop);
            KEM.Encapsulator encr = kemPlus.newEncapsulator(publicKeyPlus);
            KEM.Encapsulated enc = encr.encapsulate(0,32,"AES");

            SecretKey keyE = enc.key();

            KEM.Decapsulator decr = kemInterop.newDecapsulator(privateKeyInterop);

            SecretKey keyD = decr.decapsulate(enc.encapsulation(),0,32,"AES");
         
            assertTrue(Arrays.equals(keyE.getEncoded(), keyD.getEncoded()), "Secrets do NOT match");
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "KEMInteropCreatesPlusGet failed");
        }
    }
/* 
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
    }*/

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

