/*
 * Copyright IBM Corp. 2023, 2026
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
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

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

        //This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
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
    public void testPQCKeyGenKEMAutoKeyConvertion() throws Exception {
        String pqcAlgorithm = "ML-KEM-512";

        //This is not in the FIPS provider yet and BouncyCastle  does not support this test.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        KEM kemInterop = KEM.getInstance(pqcAlgorithm, getProviderName());

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(pqcAlgorithm, getInteropProviderName());
        KeyPair keyPair = generateKeyPair(keyPairGen);

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
            
        KEM.Encapsulator encr = kemInterop.newEncapsulator(publicKey);
        KEM.Encapsulated enc = encr.encapsulate(0, 32, "AES");
        if (enc == null) {
            System.out.println("enc = null");
            fail("KEMPlusCreatesInteropGet failed no enc.");
        }
        SecretKey keyE = enc.key();

        KEM.Decapsulator decr = kemInterop.newDecapsulator(privateKey);
        SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 32, "AES");

        assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
    } 

    @Test
    public void testPQCKeyGenKEM_Interop() throws Exception {
        String pqcAlgorithm = "ML-KEM-512";
        boolean same = false;

        //This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        // BC provider generates seed format privatekey
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));
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

        //This is not in the FIPS provider yet and Bouncy Castle does not support this test.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

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

    /**
     * Tests ML-DSA key interoperability (OpenJCEPlus → interop provider) for all
     * three parameter sets.  A key pair is generated by OpenJCEPlus, encoded, and
     * then imported by the interop provider.  Public-key byte equality is verified;
     * private-key byte equality is only checked against SunJCE because BC uses a
     * different private-key encoding.
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testPQCKeyGenMLDSA_PlusToInterop(String pqcAlgorithm) throws Exception {
        boolean same = false;

        //This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

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
        //BC is using a different encoding today for their ML-DSA private keys.
        // So we cannot compare these today.
        if (getInteropProviderName().equals(Utils.PROVIDER_SunJCE)) {
            PrivateKey privateKeyInterop = keyFactoryInterop.generatePrivate(privateKeySpecPlus);
            same = Arrays.equals(privateKeyBytesPlus, privateKeyInterop.getEncoded());
            assertTrue(same, "Private key bytes differ for " + pqcAlgorithm);
        }

        // The original and new keys are the same
        same = Arrays.equals(publicKeyBytesPlus, publicKeyInterop.getEncoded());
        assertTrue(same, "Public key bytes differ for " + pqcAlgorithm);
    }

    /**
     * Tests ML-DSA key interoperability (interop provider → OpenJCEPlus) for all
     * three parameter sets.  A key pair is generated by the interop provider,
     * encoded, and imported by OpenJCEPlus.  Public-key byte equality is verified.
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testPQCKeyGenMLDSA_Interop(String pqcAlgorithm) throws Exception {
        boolean same = false;

        //This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        // BC provider generates seed format privatekey
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

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

        //BC is using a different encoding today for their ML-DSA private keys.
        // So we cannot compare these today.
        if (getInteropProviderName().equals(Utils.PROVIDER_SunJCE)) {
            same = Arrays.equals(privateKeyBytesInterop, privateKeyPlus.getEncoded());
            assertTrue(same, "Private key bytes differ for " + pqcAlgorithm);
        }

        same = Arrays.equals(publicKeyBytesInterop, publicKeyPlus.getEncoded());
        assertTrue(same, "Public key bytes differ for " + pqcAlgorithm);
    }

    /**
     * Tests ML-DSA RAW key-spec interoperability (interop provider → OpenJCEPlus) for all
     * three parameter sets.  Uses {@code getKeySpec(key, EncodedKeySpec.class)} to obtain
     * the raw encoding from the interop provider then imports it into OpenJCEPlus.
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testPQCKeyGenMLDSA_PlusToInteropRAW(String pqcAlgorithm) throws Exception {
        boolean same = false;

        //This is not in the FIPS provider yet and Bouncy Castle does not support this test.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

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

        //BC is using a different encoding today for their ML-DSA private keys.
        // So we cannot compare these today.
        if (getInteropProviderName().equals(Utils.PROVIDER_SunJCE)) {
            same = Arrays.equals(privateKeyBytesInterop, priv.getEncoded());
            assertTrue(same, "Private key bytes differ for " + pqcAlgorithm);
        }

        // The original and new keys are the same
        same = Arrays.equals(publicKeyBytesInterop, pub.getEncoded());
        assertTrue(same, "Public key bytes differ for " + pqcAlgorithm);
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
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testSignInteropAndVerifyPlus(String algorithm) throws Exception {
        //This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(algorithm.equalsIgnoreCase("ML-DSA") && getInteropProviderName2().equalsIgnoreCase("BC"));

        try {
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
            throw ex;
        }
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testSignInteropKeysPlusSignVerify(String algorithm) {
        //This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName2()));

        try {
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
            fail("SignInteropAndVerifyPlus failed");
        }
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testSignPlusKeysInteropSignVerify(String algorithm) {
        //This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName2()));

        try {
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
            fail("SignInteropAndVerifyPlus failed");
        }
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testSignPlusAndVerifyInterop(String algorithm) {
        try {
            //This is not in the FIPS provider yet.
            assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

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
            fail("SignPlusAndVerifyInterop failed");
        }
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testKEMPlusKeyInteropAll(String Algorithm) {
        //This is not in the FIPS provider yet and Oracle Private keys have an extra Octet in them.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        try {
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
            KEM.Encapsulated enc = encr.encapsulate(0, 32, "AES");
            if (enc == null) {
                System.out.println("enc = null");
                fail("KEMPlusCreatesInteropGet failed no enc.");
            }
            SecretKey keyE = enc.key();

            KEM.Decapsulator decr = kemInterop.newDecapsulator(privateKeyInterop);
            SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 32, "AES");

            assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("KEMPlusCreatesInteropGet failed");
        }
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testKEMInteropKeyPlusAll(String Algorithm) {
        //This is not in the FIPS provider yet and Oracle Private keys have an extra Octet in them.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        try {
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
            KEM.Encapsulated enc = encr.encapsulate(0, 32, "AES");
            if (enc == null) {
                System.out.println("enc = null");
                fail("KEMPlusCreatesInteropGet failed no enc.");
            }
            SecretKey keyE = enc.key();

            KEM.Decapsulator decr = kemPlus.newDecapsulator(privateKeyPlus);
            SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 32, "AES");

            assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("KEMPlusCreatesInteropGet failed");
        }
    }
        
    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testKEMPlusCreatesInteropGet(String Algorithm) {
        try {
            //This is not in the FIPS provider yet and Oracle Private keys have an extra Octet in them.
            assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

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
            KEM.Encapsulated enc = encr.encapsulate(0, 32, "AES");
            if (enc == null) {
                System.out.println("enc = null");
                fail("KEMPlusCreatesInteropGet failed no enc.");
            }
            SecretKey keyE = enc.key();

            KEM.Decapsulator decr = kemPlus.newDecapsulator(privateKeyPlus);
            SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 32, "AES");

            assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("KEMPlusCreatesInteropGet failed");
        }
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testKEMInteropCreatesPlusGet(String Algorithm) {
        try {
            //This is not in the FIPS provider yet and Oracle Private keys have an extra Octet in them.
            assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

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
            KEM.Encapsulated enc = encr.encapsulate(0, 32, "AES");

            SecretKey keyE = enc.key();

            KEM.Decapsulator decr = kemInterop.newDecapsulator(privateKeyInterop);

            SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 32, "AES");

            assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("KEMInteropCreatesPlusGet failed");
        }
    }

    /**
     * Test ML-KEM interoperability using NamedParameterSpec to initialize KeyPairGenerator.
     * Tests encapsulation / decapsulation with different providers.
     *
     * @param parameterSet The ML-KEM parameter set (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
     * @throws Exception if any cryptographic operation fails
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testMLKEMInteropWithNamedParameterSpec(String parameterSet) throws Exception {
        // Not in FIPS provider yet and BC doesn't support this test
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        // Generate key pair using NamedParameterSpec with provider
        KeyPairGenerator keyPairGenPlus = KeyPairGenerator.getInstance("ML-KEM", getProviderName());
        keyPairGenPlus.initialize(new NamedParameterSpec(parameterSet));
        KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);
        
        // Encapsulate using provider
        KEM kemPlus = KEM.getInstance("ML-KEM", getProviderName());
        KEM.Encapsulator encapsulator = kemPlus.newEncapsulator(keyPairPlus.getPublic());
        KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, 32, "AES");
        
        SecretKey encapKey = encapsulated.key();
        byte[] encapsulation = encapsulated.encapsulation();
        
        // Decapsulate using interop provider
        KEM kemInterop = KEM.getInstance("ML-KEM", getInteropProviderName());
        KEM.Decapsulator decapsulator = kemInterop.newDecapsulator(keyPairPlus.getPrivate());
        SecretKey decapKey = decapsulator.decapsulate(encapsulation, 0, 32, "AES");
        
        // Verify that both keys match
        assertArrayEquals(encapKey.getEncoded(), decapKey.getEncoded(),
                "Encapsulated and decapsulated keys do not match for " + parameterSet);
    }

    /**
     * Test ML-KEM interoperability with empty parameters using NamedParameterSpec.
     * Tests encapsulation and decapsulation without from/to specification.
     *
     * @param parameterSet The ML-KEM parameter set (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
     * @throws Exception if any cryptographic operation fails
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testMLKEMInteropEmptyParamsWithNamedParameterSpec(String parameterSet) throws Exception {
        // Not in FIPS provider yet and BC doesn't support this test
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        // Generate key pair using NamedParameterSpec with interop provider
        KeyPairGenerator keyPairGenInterop = KeyPairGenerator.getInstance("ML-KEM", getInteropProviderName());
        keyPairGenInterop.initialize(new NamedParameterSpec(parameterSet));
        KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);
        
        // Encapsulate using interop provider (no from/to parameters)
        KEM kemInterop = KEM.getInstance("ML-KEM", getInteropProviderName());
        KEM.Encapsulator encapsulator = kemInterop.newEncapsulator(keyPairInterop.getPublic());
        KEM.Encapsulated encapsulated = encapsulator.encapsulate();
        
        SecretKey encapKey = encapsulated.key();
        byte[] encapsulation = encapsulated.encapsulation();
        
        // Decapsulate using provider (no from/to parameters)
        KEM kemPlus = KEM.getInstance("ML-KEM", getProviderName());
        KEM.Decapsulator decapsulator = kemPlus.newDecapsulator(keyPairInterop.getPrivate());
        SecretKey decapKey = decapsulator.decapsulate(encapsulation);
        
        // Verify that both keys match
        assertArrayEquals(encapKey.getEncoded(), decapKey.getEncoded(),
                "Encapsulated and decapsulated keys do not match for " + parameterSet);
    }

    /**
     * Test ML-KEM interoperability with smaller secret size using NamedParameterSpec.
     * Tests with 16 bytes instead of the default 32 bytes.
     *
     * @param parameterSet The ML-KEM parameter set (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
     * @throws Exception if any cryptographic operation fails
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testMLKEMInteropSmallerSecretWithNamedParameterSpec(String parameterSet) throws Exception {
        // Not in FIPS provider yet and BC doesn't support this test
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        // Generate key pair using NamedParameterSpec with provider
        KeyPairGenerator keyPairGenPlus = KeyPairGenerator.getInstance("ML-KEM", getProviderName());
        keyPairGenPlus.initialize(new NamedParameterSpec(parameterSet));
        KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);
        
        // Encapsulate using provider with smaller secret (16 bytes)
        KEM kemPlus = KEM.getInstance("ML-KEM", getProviderName());
        KEM.Encapsulator encapsulator = kemPlus.newEncapsulator(keyPairPlus.getPublic());
        KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, 16, "AES");
        
        SecretKey encapKey = encapsulated.key();
        byte[] encapsulation = encapsulated.encapsulation();
        
        // Decapsulate using interop provider with same secret size
        KEM kemInterop = KEM.getInstance("ML-KEM", getInteropProviderName());
        KEM.Decapsulator decapsulator = kemInterop.newDecapsulator(keyPairPlus.getPrivate());
        SecretKey decapKey = decapsulator.decapsulate(encapsulation, 0, 16, "AES");
        
        // Verify that both keys match
        assertArrayEquals(encapKey.getEncoded(), decapKey.getEncoded(),
                "Encapsulated and decapsulated keys do not match for " + parameterSet);
    }

    /**
     * Test bidirectional ML-KEM interoperability using NamedParameterSpec.
     * Tests both directions to and from providers.
     *
     * @param parameterSet The ML-KEM parameter set (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
     * @throws Exception if any cryptographic operation fails
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testMLKEMBidirectionalInteropWithNamedParameterSpec(String parameterSet) throws Exception {
        // Not in FIPS provider yet and BC doesn't support this test
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        // Test 1: Generate with provider, encapsulate with interop provider, decapsulate with provider
        KeyPairGenerator keyPairGenPlus = KeyPairGenerator.getInstance("ML-KEM", getProviderName());
        keyPairGenPlus.initialize(new NamedParameterSpec(parameterSet));
        KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);
        
        KEM kemInterop = KEM.getInstance("ML-KEM", getInteropProviderName());
        KEM.Encapsulator encapsulatorInterop = kemInterop.newEncapsulator(keyPairPlus.getPublic());
        KEM.Encapsulated encapsulatedInterop = encapsulatorInterop.encapsulate(0, 32, "AES");
        
        KEM kemPlus = KEM.getInstance("ML-KEM", getProviderName());
        KEM.Decapsulator decapsulatorPlus = kemPlus.newDecapsulator(keyPairPlus.getPrivate());
        SecretKey decapKeyPlus = decapsulatorPlus.decapsulate(encapsulatedInterop.encapsulation(), 0, 32, "AES");
        
        assertArrayEquals(encapsulatedInterop.key().getEncoded(), decapKeyPlus.getEncoded(),
                "Keys do not match for test 1 with " + parameterSet);
        
        // Test 2: Generate with interop provider, encapsulate with provider, decapsulate with interop provider
        KeyPairGenerator keyPairGenInterop = KeyPairGenerator.getInstance("ML-KEM", getInteropProviderName());
        keyPairGenInterop.initialize(new NamedParameterSpec(parameterSet));
        KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);
        
        KEM.Encapsulator encapsulatorPlus = kemPlus.newEncapsulator(keyPairInterop.getPublic());
        KEM.Encapsulated encapsulatedPlus = encapsulatorPlus.encapsulate(0, 32, "AES");
        
        KEM.Decapsulator decapsulatorInterop = kemInterop.newDecapsulator(keyPairInterop.getPrivate());
        SecretKey decapKeyInterop = decapsulatorInterop.decapsulate(encapsulatedPlus.encapsulation(), 0, 32, "AES");
        
        assertArrayEquals(encapsulatedPlus.key().getEncoded(), decapKeyInterop.getEncoded(),
                "Keys do not match for test 2 with " + parameterSet);
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testMLKEMGetKeySpecPrivateInteropToPlus(String algorithm)
            throws Exception {
        // This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        KeyFactory openjceplusKeyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        KeyPairGenerator interopKpg = KeyPairGenerator.getInstance(algorithm, getInteropProviderName());
        KeyPair interopKeyPair = interopKpg.generateKeyPair();
        PrivateKey interopPrivateKey = interopKeyPair.getPrivate();
        KeySpec interopPrivKeySpec = new PKCS8EncodedKeySpec(interopPrivateKey.getEncoded());
        PrivateKey openjceplusPrivateKey = openjceplusKeyFactory.generatePrivate(interopPrivKeySpec);

        KEM interopKem = KEM.getInstance(algorithm, getInteropProviderName());
        KEM.Encapsulator encapsulator =
                interopKem.newEncapsulator(interopKeyPair.getPublic());

        KEM.Encapsulated encapsulated = encapsulator.encapsulate();

        KEM openjceplusKem = KEM.getInstance(algorithm, getProviderName());
        KEM.Decapsulator decapsulator =
                openjceplusKem.newDecapsulator(openjceplusPrivateKey);

        SecretKey openjceplusSecret =
                decapsulator.decapsulate(encapsulated.encapsulation());

        assertArrayEquals(encapsulated.key().getEncoded(),
            openjceplusSecret.getEncoded());

        KeySpec keySpec = openjceplusKeyFactory.getKeySpec(openjceplusPrivateKey, interopPrivKeySpec.getClass());
        assertEquals(interopPrivKeySpec.getClass(), keySpec.getClass());
        assertPrivateKeyPKCS8SpecEquals(interopPrivKeySpec, keySpec);
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testMLDSAGetKeySpecPrivateInteropToPlus(String algorithm)
            throws Exception {
        // This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        KeyFactory openjceplusKeyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        KeyPairGenerator interopKpg = KeyPairGenerator.getInstance(algorithm, getInteropProviderName2());
        KeyPair interopKeyPair = interopKpg.generateKeyPair();
        PrivateKey interopPrivateKey = interopKeyPair.getPrivate();
        KeySpec interopPrivKeySpec = new PKCS8EncodedKeySpec(interopPrivateKey.getEncoded());
        PrivateKey openjceplusPrivateKey = openjceplusKeyFactory.generatePrivate(interopPrivKeySpec);

        Signature signerPlus = Signature.getInstance(algorithm, getProviderName());
        signerPlus.initSign(openjceplusPrivateKey);
        signerPlus.update(origMsg);
        byte[] signaturePlus = signerPlus.sign();

        Signature verifierInterop = Signature.getInstance(algorithm, getInteropProviderName2());
        verifierInterop.initVerify(interopKeyPair.getPublic());
        verifierInterop.update(origMsg);
        assertTrue(verifierInterop.verify(signaturePlus), "Signature verification failed");
    }

    private void assertPrivateKeyPKCS8SpecEquals(KeySpec expected, KeySpec actual) {
        assertEquals(PKCS8EncodedKeySpec.class, actual.getClass());

        PKCS8EncodedKeySpec expectedSpec = (PKCS8EncodedKeySpec) expected;
        PKCS8EncodedKeySpec actualSpec = (PKCS8EncodedKeySpec) actual;

        assertArrayEquals(expectedSpec.getEncoded(), actualSpec.getEncoded());
        assertEquals(expectedSpec.getAlgorithm(), actualSpec.getAlgorithm());
        assertEquals(expectedSpec.getFormat(), actualSpec.getFormat());
    }

    /**
     * Tests that OpenJCEPlus' generic {@code KeyFactory.getInstance("ML-DSA")} can
     * import public and private keys generated by the interop provider with any
     * ML-DSA parameter set.  The re-encoded public-key bytes must be identical.
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testGenericMLDSAKeyFactoryImportsInteropKeys(String paramSetName) throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        // Generate a key pair with the interop provider using the specific param set
        keyPairGenInterop = KeyPairGenerator.getInstance(paramSetName, getInteropProviderName2());
        KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);

        byte[] x509Bytes  = keyPairInterop.getPublic().getEncoded();
        byte[] pkcs8Bytes = keyPairInterop.getPrivate().getEncoded();

        // Import via the GENERIC "ML-DSA" KeyFactory on the OpenJCEPlus side
        KeyFactory genericKF = KeyFactory.getInstance("ML-DSA", getProviderName());

        PublicKey pub = genericKF.generatePublic(new X509EncodedKeySpec(x509Bytes));
        assertTrue(Arrays.equals(x509Bytes, pub.getEncoded()),
                "Generic ML-DSA KF: re-encoded public key bytes differ for " + paramSetName);

        // BC private-key encoding differs; only compare against SunJCE
        if (getInteropProviderName().equals(Utils.PROVIDER_SunJCE)) {
            PrivateKey priv = genericKF.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Bytes));
            assertTrue(Arrays.equals(pkcs8Bytes, priv.getEncoded()),
                    "Generic ML-DSA KF: re-encoded private key bytes differ for " + paramSetName);
        }
    }

    /**
     * Tests that keys generated by OpenJCEPlus' generic {@code KeyPairGenerator("ML-DSA")}
     * (which defaults to ML-DSA-65) can be imported by the interop provider and used
     * for a successful sign/verify round-trip.
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testMLDSAInteropWithNamedParameterSpec(String paramSetName) throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        // Generate a key pair on the OpenJCEPlus side using generic KPG + NamedParameterSpec
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", getProviderName());
        kpg.initialize(new NamedParameterSpec(paramSetName));
        KeyPair keyPairPlus = generateKeyPair(kpg);

        // Import public key into the interop provider
        KeyFactory kfInterop = KeyFactory.getInstance(paramSetName, getInteropProviderName2());
        PublicKey pubInterop = kfInterop.generatePublic(
                new X509EncodedKeySpec(keyPairPlus.getPublic().getEncoded()));

        assertTrue(Arrays.equals(keyPairPlus.getPublic().getEncoded(), pubInterop.getEncoded()),
                "Public key bytes differ after import into interop provider for " + paramSetName);

        // Sign with OpenJCEPlus generic "ML-DSA" Signature
        Signature sigPlus = Signature.getInstance("ML-DSA", getProviderName());
        sigPlus.initSign(keyPairPlus.getPrivate());
        sigPlus.update(origMsg);
        byte[] sigBytes = sigPlus.sign();

        // Verify with interop provider using the param-set-specific Signature
        Signature sigInterop = Signature.getInstance(paramSetName, getInteropProviderName2());
        sigInterop.initVerify(pubInterop);
        sigInterop.update(origMsg);
        assertTrue(sigInterop.verify(sigBytes),
                "Interop verify failed for signature produced by generic ML-DSA / " + paramSetName);
    }

    /**
     * Tests that a signature produced by the interop provider can be verified by
     * OpenJCEPlus' generic {@code Signature.getInstance("ML-DSA")} instance using a
     * key imported via the generic {@code KeyFactory.getInstance("ML-DSA")}.
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testGenericMLDSASignatureInteropSignsPlusVerifies(String paramSetName) throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        // Generate and sign with the interop provider
        keyPairGenInterop = KeyPairGenerator.getInstance(paramSetName, getInteropProviderName2());
        KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);

        Signature sigInterop = Signature.getInstance(paramSetName, getInteropProviderName2());
        sigInterop.initSign(keyPairInterop.getPrivate());
        sigInterop.update(origMsg);
        byte[] sigBytes = sigInterop.sign();

        // Import public key into OpenJCEPlus via generic "ML-DSA" KeyFactory
        KeyFactory genericKF = KeyFactory.getInstance("ML-DSA", getProviderName());
        PublicKey pubPlus = genericKF.generatePublic(
                new X509EncodedKeySpec(keyPairInterop.getPublic().getEncoded()));

        // Verify with OpenJCEPlus generic "ML-DSA" Signature
        Signature sigPlus = Signature.getInstance("ML-DSA", getProviderName());
        sigPlus.initVerify(pubPlus);
        sigPlus.update(origMsg);
        assertTrue(sigPlus.verify(sigBytes),
                "Generic ML-DSA Signature failed to verify interop signature for " + paramSetName);
    }

    /**
     * Tests a full cross-provider sign/verify round-trip using the generic
     * "ML-DSA" API on the OpenJCEPlus side and the param-set-specific API on the
     * interop side, for all three ML-DSA parameter sets.
     *
     * <p>OpenJCEPlus signs → interop verifies, then interop signs → OpenJCEPlus verifies.
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testGenericMLDSASignatureBidirectionalInterop(String paramSetName) throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        // --- Direction 1: OpenJCEPlus signs, interop verifies ---

        // Generate on OpenJCEPlus with specific param-set KPG
        keyPairGenPlus = KeyPairGenerator.getInstance(paramSetName, getProviderName());
        KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);

        // Sign with OpenJCEPlus generic "ML-DSA" Signature
        Signature sigPlus = Signature.getInstance("ML-DSA", getProviderName());
        sigPlus.initSign(keyPairPlus.getPrivate());
        sigPlus.update(origMsg);
        byte[] sigFromPlus = sigPlus.sign();

        // Import public key into interop via specific param-set KF, then verify
        KeyFactory kfInterop = KeyFactory.getInstance(paramSetName, getInteropProviderName2());
        PublicKey pubInterop = kfInterop.generatePublic(
                new X509EncodedKeySpec(keyPairPlus.getPublic().getEncoded()));
        Signature sigInteropVerify = Signature.getInstance(paramSetName, getInteropProviderName2());
        sigInteropVerify.initVerify(pubInterop);
        sigInteropVerify.update(origMsg);
        assertTrue(sigInteropVerify.verify(sigFromPlus),
                "Interop failed to verify OpenJCEPlus generic ML-DSA signature for " + paramSetName);

        // --- Direction 2: interop signs, OpenJCEPlus verifies ---

        // Generate on interop with specific param-set KPG
        keyPairGenInterop = KeyPairGenerator.getInstance(paramSetName, getInteropProviderName2());
        KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);

        Signature sigInteropSign = Signature.getInstance(paramSetName, getInteropProviderName2());
        sigInteropSign.initSign(keyPairInterop.getPrivate());
        sigInteropSign.update(origMsg);
        byte[] sigFromInterop = sigInteropSign.sign();

        // Import public key into OpenJCEPlus via generic "ML-DSA" KF, then verify with generic Sig
        KeyFactory genericKF = KeyFactory.getInstance("ML-DSA", getProviderName());
        PublicKey pubPlus = genericKF.generatePublic(
                new X509EncodedKeySpec(keyPairInterop.getPublic().getEncoded()));
        Signature sigPlusVerify = Signature.getInstance("ML-DSA", getProviderName());
        sigPlusVerify.initVerify(pubPlus);
        sigPlusVerify.update(origMsg);
        assertTrue(sigPlusVerify.verify(sigFromInterop),
                "OpenJCEPlus generic ML-DSA failed to verify interop signature for " + paramSetName);
    }

    /**
     * Asserts that {@code key.getAlgorithm()} returns {@code "ML-DSA"} for every
     * ML-DSA parameter set on both the interop provider and on OpenJCEPlus after
     * round-tripping through encoded form.
     *
     * <p>Both providers must agree on the family name per JEP 497.  The BC
     * provider is excluded because it intentionally returns the param-set name
     * (e.g. {@code "ML-DSA-65"}) rather than the family name.
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testMLDSAGetAlgorithmConsistentAcrossProviders(String paramSetName)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        // Generate with the interop provider (SUN)
        KeyPair interopKP = KeyPairGenerator.getInstance(paramSetName, getInteropProviderName2())
                                            .generateKeyPair();
        String interopPubAlg  = interopKP.getPublic().getAlgorithm();
        String interopPrivAlg = interopKP.getPrivate().getAlgorithm();

        // Import into OpenJCEPlus via the generic "ML-DSA" KeyFactory
        KeyFactory kf = KeyFactory.getInstance("ML-DSA", getProviderName());
        PublicKey  plusPub  = kf.generatePublic(
                new X509EncodedKeySpec(interopKP.getPublic().getEncoded()));
        PrivateKey plusPriv = kf.generatePrivate(
                new PKCS8EncodedKeySpec(interopKP.getPrivate().getEncoded()));

        // Both providers must return the same algorithm name
        assertEquals(interopPubAlg, plusPub.getAlgorithm(),
                "Public key getAlgorithm() mismatch between " + getInteropProviderName2()
                + " and " + getProviderName() + " for " + paramSetName);
        assertEquals(interopPrivAlg, plusPriv.getAlgorithm(),
                "Private key getAlgorithm() mismatch between " + getInteropProviderName2()
                + " and " + getProviderName() + " for " + paramSetName);

        // OpenJCEPlus must return the canonical family name
        assertEquals("ML-DSA", plusPub.getAlgorithm(),
                "OpenJCEPlus public key should return family name \"ML-DSA\" for " + paramSetName);
        assertEquals("ML-DSA", plusPriv.getAlgorithm(),
                "OpenJCEPlus private key should return family name \"ML-DSA\" for " + paramSetName);
    }

    /**
     * Asserts that {@code key.getAlgorithm()} returns {@code "ML-KEM"} for every
     * ML-KEM parameter set on both the interop provider and on OpenJCEPlus after
     * round-tripping through encoded form.
     *
     * <p>Both providers must agree on the family name per JEP 497.  The BC
     * provider is excluded because it intentionally returns the param-set name
     * (e.g. {@code "ML-KEM-512"}) rather than the family name.
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testMLKEMGetAlgorithmConsistentAcrossProviders(String paramSetName)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        // Generate with the interop provider (SunJCE)
        KeyPair interopKP = KeyPairGenerator.getInstance(paramSetName, getInteropProviderName())
                                            .generateKeyPair();
        String interopPubAlg  = interopKP.getPublic().getAlgorithm();
        String interopPrivAlg = interopKP.getPrivate().getAlgorithm();

        // Import into OpenJCEPlus
        KeyFactory kf = KeyFactory.getInstance(paramSetName, getProviderName());
        PublicKey  plusPub  = kf.generatePublic(
                new X509EncodedKeySpec(interopKP.getPublic().getEncoded()));
        PrivateKey plusPriv = kf.generatePrivate(
                new PKCS8EncodedKeySpec(interopKP.getPrivate().getEncoded()));

        // Both providers must return the same algorithm name
        assertEquals(interopPubAlg, plusPub.getAlgorithm(),
                "Public key getAlgorithm() mismatch between " + getInteropProviderName()
                + " and " + getProviderName() + " for " + paramSetName);
        assertEquals(interopPrivAlg, plusPriv.getAlgorithm(),
                "Private key getAlgorithm() mismatch between " + getInteropProviderName()
                + " and " + getProviderName() + " for " + paramSetName);

        // OpenJCEPlus must return the canonical family name
        assertEquals("ML-KEM", plusPub.getAlgorithm(),
                "OpenJCEPlus public key should return family name \"ML-KEM\" for " + paramSetName);
        assertEquals("ML-KEM", plusPriv.getAlgorithm(),
                "OpenJCEPlus private key should return family name \"ML-KEM\" for " + paramSetName);
    }

}
