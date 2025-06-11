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
        boolean same = false;

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
        PrivateKey privateKeyInterop = keyFactoryInterop.generatePrivate(privateKeySpecPlus);

        // BC private keys do not currently conform to the Draft standard for these keys
        // So we know the keys will not compare
        if (getInteropProviderName().equals(Utils.PROVIDER_SunJCE)) {
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
        boolean same = false;

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

        // BC private keys do not currently conform to the Draft standard for these keys
        // So we know the keys will not compare
        if (getInteropProviderName().equals(Utils.PROVIDER_SunJCE)) {
            same = Arrays.equals(privateKeyBytesInterop, privateKeyPlus.getEncoded());
            assertTrue(same);
        }

        same = Arrays.equals(publicKeyBytesInterop, publicKeyPlus.getEncoded());
        assertTrue(same);

    }
    @Test
    public void testPQCKeyGenKEM_PlusToInteropRAW() throws Exception {
        String pqcAlgorithm = "ML-KEM-512";
        boolean same = false;

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
        PrivateKey priv = keyFactoryPlus.generatePrivate(eksPrivInterop);
        same = Arrays.equals(privateKeyBytesInterop, priv.getEncoded());
        assertTrue(same);
        
        // The original and new keys are the same
        same = Arrays.equals(publicKeyBytesInterop, pub.getEncoded());
        assertTrue(same);
    }
    @Test
    public void testPQCKeyGenMLDSA_PlusToInterop() throws Exception {
        String pqcAlgorithm = "ML-DSA-65";
        boolean same = false;

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
        PrivateKey privateKeyPlus = keyPairPlus.getPrivate();
        byte[] publicKeyBytesPlus = publicKeyPlus.getEncoded();
        byte[] privateKeyBytesPlus = privateKeyPlus.getEncoded();

        PKCS8EncodedKeySpec privateKeySpecPlus = new PKCS8EncodedKeySpec(privateKeyBytesPlus);
        EncodedKeySpec publicKeySpecPlus = new X509EncodedKeySpec(publicKeyBytesPlus);
        PublicKey publicKeyInterop = keyFactoryInterop.generatePublic(publicKeySpecPlus);
        //BC is using a different encoding today for thier ML-DSA private keys.
        // So we can not compare these today.
        if (getInteropProviderName().equals(Utils.PROVIDER_SunJCE)) {
            PrivateKey privateKeyInterop = keyFactoryInterop.generatePrivate(privateKeySpecPlus);
            same = Arrays.equals(privateKeyBytesPlus, privateKeyInterop.getEncoded());
            assertTrue(same);
        }
        
        // The original and new keys are the same
        same = Arrays.equals(publicKeyBytesPlus, publicKeyInterop.getEncoded());
        assertTrue(same);
    } 
    @Test
    public void testPQCKeyGenMLDSA_Interop() throws Exception {        
        String pqcAlgorithm = "ML-DSA-65";
        boolean same = false;

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

        //BC is using a different encoding today for thier ML-DSA private keys.
        // So we can not compare these today.
        if (getInteropProviderName().equals(Utils.PROVIDER_SunJCE)) {
            same = Arrays.equals(privateKeyBytesInterop, privateKeyPlus.getEncoded());
            assertTrue(same);
        }  

        same = Arrays.equals(publicKeyBytesInterop, publicKeyPlus.getEncoded());
        assertTrue(same);

    }
    @Test
    public void testPQCKeyGenMLDSA_PlusToInteropRAW() throws Exception {
        String pqcAlgorithm = "ML-DSA-65";
        boolean same = false;

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
        PrivateKey privateKeyInterop = keyPairInterop.getPrivate();
        byte[] publicKeyBytesInterop = publicKeyInterop.getEncoded();
        byte[] privateKeyBytesInterop = privateKeyInterop.getEncoded();

        EncodedKeySpec eksInterop = keyFactoryInterop.getKeySpec(publicKeyInterop, EncodedKeySpec.class);
        PublicKey pub = keyFactoryPlus.generatePublic(eksInterop); 
        EncodedKeySpec eksPrivInterop = keyFactoryInterop.getKeySpec(privateKeyInterop, EncodedKeySpec.class);
        PrivateKey priv = keyFactoryPlus.generatePrivate(eksPrivInterop);
        
        //BC is using a different encoding today for thier ML-DSA private keys.
        // So we can not compare these today.
        if (getInteropProviderName().equals(Utils.PROVIDER_SunJCE)) {
            same = Arrays.equals(privateKeyBytesInterop, priv.getEncoded());
            assertTrue(same);
        }
        
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
    public void testSignInteropKeysPlusSignVerify(String algorithm) {
        try {
            if (getProviderName().equals("OpenJCEPlusFIPS") || 
                getInteropProviderName().equals(Utils.PROVIDER_BC)) {
                //This is not in the FIPS provider yet.
                return;
            }
            keyPairGenInterop = KeyPairGenerator.getInstance(algorithm, getInteropProviderName2());
            KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);

            PublicKey publicKeyInterop = keyPairInterop.getPublic();
            PrivateKey privateKeyInterop = keyPairInterop.getPrivate();
            PKCS8EncodedKeySpec privateKeySpecInterop = new PKCS8EncodedKeySpec(privateKeyInterop.getEncoded());
            EncodedKeySpec publicKeySpecInterop = new X509EncodedKeySpec(publicKeyInterop.getEncoded());
            KeyFactory keyFactoryPlus = KeyFactory.getInstance(algorithm, getProviderName());
            PrivateKey privPlus = keyFactoryPlus.generatePrivate(privateKeySpecInterop);
            PublicKey pubPlus = keyFactoryPlus.generatePublic(publicKeySpecInterop);

            Signature signingInterop = Signature.getInstance(algorithm, getProviderName());
            signingInterop.initSign(privPlus);
            signingInterop.update(origMsg);
            byte[] signedBytesInterop = signingInterop.sign();

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
    public void testSignPlusKeysInteropSignVerify(String algorithm) {
        try {
            if (getProviderName().equals("OpenJCEPlusFIPS") || 
                getInteropProviderName().equals(Utils.PROVIDER_BC)) {
                //This is not in the FIPS provider yet.
                return;
            }
            keyPairGenPlus = KeyPairGenerator.getInstance(algorithm, getProviderName());
            KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);

            PublicKey publicKeyPlus = keyPairPlus.getPublic();
            PrivateKey privateKeyPlus = keyPairPlus.getPrivate();
            PKCS8EncodedKeySpec privateKeySpecPlus = new PKCS8EncodedKeySpec(privateKeyPlus.getEncoded());
            EncodedKeySpec publicKeySpecPlus = new X509EncodedKeySpec(publicKeyPlus.getEncoded());
            KeyFactory keyFactoryInterop = KeyFactory.getInstance(algorithm, getInteropProviderName2());
            PrivateKey privInterop = keyFactoryInterop.generatePrivate(privateKeySpecPlus);
            PublicKey pubInterop = keyFactoryInterop.generatePublic(publicKeySpecPlus);

            Signature signingInterop = Signature.getInstance(algorithm, getInteropProviderName2());
            signingInterop.initSign(privInterop);
            signingInterop.update(origMsg);
            byte[] signedBytesInterop = signingInterop.sign();

            Signature verifyingPlus = Signature.getInstance(algorithm, getInteropProviderName2());
            verifyingPlus.initVerify(pubInterop);
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
    public void testKEMPlusKeyInteropAll(String Algorithm) {
        try {
            if (getProviderName().equals("OpenJCEPlusFIPS") || 
                getInteropProviderName().equals(Utils.PROVIDER_BC)) {
                //This is not in the FIPS provider yet and Oracle Private keys have an extra Octet in them.
                return;
            }

            KEM kemInterop = KEM.getInstance("ML-KEM", getInteropProviderName());

            keyPairGenPlus = KeyPairGenerator.getInstance(Algorithm, getProviderName());
            KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);

            PublicKey publicKeyPlus = keyPairPlus.getPublic();
            PrivateKey privateKeyPlus = keyPairPlus.getPrivate();
            
            PKCS8EncodedKeySpec privateKeySpecPlus = new PKCS8EncodedKeySpec(privateKeyPlus.getEncoded());
            EncodedKeySpec publicKeySpecPlus = new X509EncodedKeySpec(publicKeyPlus.getEncoded());
            KeyFactory keyFactoryPlus = KeyFactory.getInstance(Algorithm, getInteropProviderName());
            PrivateKey privateKeyInterop = keyFactoryPlus.generatePrivate(privateKeySpecPlus);
            PublicKey publicKeyInterop = keyFactoryPlus.generatePublic(publicKeySpecPlus);

            KEM.Encapsulator encr = kemInterop.newEncapsulator(publicKeyInterop);
            KEM.Encapsulated enc = encr.encapsulate(0,31,"AES");
            if (enc == null){
                System.out.println("enc = null");
                assertTrue(false, "KEMPlusCreatesInteropGet failed no enc.");
            }
            SecretKey keyE = enc.key();
           
            KEM.Decapsulator decr = kemInterop.newDecapsulator(privateKeyInterop);
            SecretKey keyD = decr.decapsulate(enc.encapsulation(),0,31,"AES");

            assertTrue(Arrays.equals(keyE.getEncoded(), keyD.getEncoded()), "Secrets do NOT match");
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "KEMPlusCreatesInteropGet failed");
        }
    }
     
    @ParameterizedTest
    @CsvSource({"ML-KEM-512","ML-KEM-768","ML-KEM-1024"})
    public void testKEMInteropKeyPlusAll(String Algorithm) {
        try {
            if (getProviderName().equals("OpenJCEPlusFIPS") || 
                getInteropProviderName().equals(Utils.PROVIDER_BC)) {
                //This is not in the FIPS provider yet and Oracle Private keys have an extra Octet in them.
                return;
            }

            KEM kemPlus = KEM.getInstance(Algorithm, getProviderName());

            keyPairGenInterop = KeyPairGenerator.getInstance(Algorithm, getInteropProviderName());
            KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);

            PublicKey publicKeyInterop = keyPairInterop.getPublic();
            PrivateKey privateKeyInterop = keyPairInterop.getPrivate();
            
            PKCS8EncodedKeySpec privateKeySpecInterop = new PKCS8EncodedKeySpec(privateKeyInterop.getEncoded());
            EncodedKeySpec publicKeySpecInterop = new X509EncodedKeySpec(publicKeyInterop.getEncoded());
            KeyFactory keyFactoryPlus = KeyFactory.getInstance(Algorithm, getProviderName());
            PrivateKey privateKeyPlus = keyFactoryPlus.generatePrivate(privateKeySpecInterop);
            PublicKey publicKeyPlus = keyFactoryPlus.generatePublic(publicKeySpecInterop);

            KEM.Encapsulator encr = kemPlus.newEncapsulator(publicKeyPlus);
            KEM.Encapsulated enc = encr.encapsulate(0,31,"AES");
            if (enc == null){
                System.out.println("enc = null");
                assertTrue(false, "KEMPlusCreatesInteropGet failed no enc.");
            }
            SecretKey keyE = enc.key();
           
            KEM.Decapsulator decr = kemPlus.newDecapsulator(privateKeyPlus);
            SecretKey keyD = decr.decapsulate(enc.encapsulation(),0,31,"AES");

            assertTrue(Arrays.equals(keyE.getEncoded(), keyD.getEncoded()), "Secrets do NOT match");
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "KEMPlusCreatesInteropGet failed");
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
            KEM.Encapsulated enc = encr.encapsulate(0,31,"AES");
            if (enc == null){
                System.out.println("enc = null");
                assertTrue(false, "KEMPlusCreatesInteropGet failed no enc.");
            }
            SecretKey keyE = enc.key();
           
            KEM.Decapsulator decr = kemPlus.newDecapsulator(privateKeyPlus);
            SecretKey keyD = decr.decapsulate(enc.encapsulation(),0,31,"AES");

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
            KEM.Encapsulated enc = encr.encapsulate(0,31,"AES");

            SecretKey keyE = enc.key();

            KEM.Decapsulator decr = kemInterop.newDecapsulator(privateKeyInterop);

            SecretKey keyD = decr.decapsulate(enc.encapsulation(),0,31,"AES");
         
            assertTrue(Arrays.equals(keyE.getEncoded(), keyD.getEncoded()), "Secrets do NOT match");
        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "KEMInteropCreatesPlusGet failed");
        }
    }

}

