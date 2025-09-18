/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestKEM extends BaseTestJunit5 {


    protected KeyPairGenerator pqcKeyPairGen;
    protected KeyFactory pqcKeyFactory;

    @ParameterizedTest
    @CsvSource({"ML-KEM-512","ML_KEM_768","ML_KEM_1024"})
    public void testKEM(String Algorithm) throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support PQC keys currently
            return;
        }
        KEM kem = KEM.getInstance(Algorithm, getProviderName());

        KeyPair pqcKeyPair = generateKeyPair(Algorithm);
        pqcKeyPair.getPublic();
        pqcKeyPair.getPrivate();

        KEM.Encapsulator encr = kem.newEncapsulator(pqcKeyPair.getPublic());
        KEM.Encapsulated enc = encr.encapsulate(0,32,"AES");

        SecretKey keyE = enc.key();
       
        KEM.Decapsulator decr = kem.newDecapsulator(pqcKeyPair.getPrivate());
        SecretKey keyD = decr.decapsulate(enc.encapsulation(),0,32,"AES");
        
        assertArrayEquals(keyE.getEncoded(),keyD.getEncoded(),"Secrets do NOT match");
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM-512","ML_KEM_768","ML_KEM_1024"})
    public void testKEMEmptyNoToFrom(String Algorithm) throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support PQC keys currently
            return;
        }
        KEM kem = KEM.getInstance(Algorithm, getProviderName());

        KeyPair pqcKeyPair = generateKeyPair(Algorithm);
        pqcKeyPair.getPublic();
        pqcKeyPair.getPrivate();

        KEM.Encapsulator encr = kem.newEncapsulator(pqcKeyPair.getPublic());
        KEM.Encapsulated enc = encr.encapsulate();

        SecretKey keyE = enc.key();
       
        KEM.Decapsulator decr = kem.newDecapsulator(pqcKeyPair.getPrivate());
        SecretKey keyD = decr.decapsulate(enc.encapsulation());
        
        assertArrayEquals(keyE.getEncoded(),keyD.getEncoded(),"Secrets do NOT match");
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM-512","ML_KEM_768","ML_KEM_1024"})
    public void testKEMError(String Algorithm) throws Exception {
        KEM.Encapsulated enc = null;

        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support PQC keys currently
            return;
        }
        KEM kem = KEM.getInstance(Algorithm, getProviderName());

        KeyPair pqcKeyPair = generateKeyPair(Algorithm);
        pqcKeyPair.getPublic();
        pqcKeyPair.getPrivate();

        KEM.Encapsulator encr = kem.newEncapsulator(pqcKeyPair.getPublic());
        try {
            enc = encr.encapsulate(0,33,"AES");
            assertTrue(false, "testKEMError failed -Encapsulated length too long worked.");
        } catch (IndexOutOfBoundsException iob) {

        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "testKEMError failed - Unexpected Exception" + ex.getMessage());
        }
   
        try {
            enc = encr.encapsulate(-1,32,"AES");
            assertTrue(false, "testKEMError failed -Encapsulated negative start point worked.");
        } catch (IndexOutOfBoundsException iob) {

        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "testKEMError failed - Unexpected Exception" + ex.getMessage());
        }

        try {
            enc = encr.encapsulate(20,15,"AES");
            assertTrue(false, "testKEMError failed -Encapsulated start point after to worked.");
        } catch (IndexOutOfBoundsException iob) {

        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "testKEMError failed - Unexpected Exception" + ex.getMessage());
        }

        try {
            enc = encr.encapsulate(32,32,"AES");
            assertTrue(false, "testKEMError failed -Encapsulated start point 32 worked.");
        } catch (IndexOutOfBoundsException iob) {

        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "testKEMError failed - Unexpected Exception" + ex.getMessage());
        }

        try {
            enc = encr.encapsulate(0,32,null);
            assertTrue(false, "testKEMError failed -Encapsulated null alg worked.");
        } catch (NullPointerException iob) {

        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "testKEMError failed - Unexpected Exception" + ex.getMessage());
        }

        enc = encr.encapsulate(0,32,"AES");
       
        KEM.Decapsulator decr = kem.newDecapsulator(pqcKeyPair.getPrivate());
        try {
            decr.decapsulate(enc.encapsulation(),0,33,"AES");
            assertTrue(false, "testKEMError failed -Decapsulate length too long worked.");
        } catch (IndexOutOfBoundsException iob) {

        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "testKEMError failed - Unexpected Exception" + ex.getMessage());
        }

        try {
            decr.decapsulate(enc.encapsulation(),-1,32,"AES");
            assertTrue(false, "testKEMError failed -Decapsulate negative start point worked.");
        } catch (IndexOutOfBoundsException iob) {

        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "testKEMError failed - Unexpected Exception" + ex.getMessage());
        }   

        try {
            decr.decapsulate(enc.encapsulation(),20,15,"AES");
            assertTrue(false, "testKEMError failed -Decapsulate start point after to worked.");
        } catch (IndexOutOfBoundsException iob) {

        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "testKEMError failed - Unexpected Exception" + ex.getMessage());
        }     
        try {
            decr.decapsulate(enc.encapsulation(),32,32,"AES");
            assertTrue(false, "testKEMError failed -Decapsulate start point 32 worked.");
        } catch (IndexOutOfBoundsException iob) {

        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "testKEMError failed - Unexpected Exception" + ex.getMessage());
        }

        try {
            decr.decapsulate(enc.encapsulation(),0,32,null);
            assertTrue(false, "testKEMError failed -Decapsulate alg null worked.");
        } catch (NullPointerException iob) {

        } catch (Exception ex) {
            ex.printStackTrace();
            assertTrue(false, "testKEMError failed - Unexpected Exception" + ex.getMessage());
        }
    }
   @ParameterizedTest
    @CsvSource({"ML-KEM-512","ML_KEM_768","ML_KEM_1024"})
    public void testKEMSmallerSecret(String Algorithm) throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support PQC keys currently
            return;
        }
        KEM kem = KEM.getInstance(Algorithm, getProviderName());

        KeyPair pqcKeyPair = generateKeyPair(Algorithm);
        pqcKeyPair.getPublic();
        pqcKeyPair.getPrivate();

        KEM.Encapsulator encr = kem.newEncapsulator(pqcKeyPair.getPublic());
        KEM.Encapsulated enc = encr.encapsulate(0,16,"AES");

        SecretKey keyE = enc.key();
       
        KEM.Decapsulator decr = kem.newDecapsulator(pqcKeyPair.getPrivate());
        SecretKey keyD = decr.decapsulate(enc.encapsulation(),0,16,"AES");
        
        assertArrayEquals(keyE.getEncoded(),keyD.getEncoded(),"Secrets do NOT match");
    }

    protected KeyPair generateKeyPair(String Algorithm) throws Exception {
        pqcKeyPairGen = KeyPairGenerator.getInstance(Algorithm, getProviderName());

        KeyPair keyPair = pqcKeyPairGen.generateKeyPair();
        if (keyPair.getPrivate() == null) {
            fail("Private key is null");
        }

        if (keyPair.getPublic() == null) {
            fail("RPublic key is null");
        }

        if (!(keyPair.getPrivate() instanceof PrivateKey)) {
            fail("Key is not a PrivateKey");
        }

        if (!(keyPair.getPublic() instanceof PublicKey)) {
            fail("Key is not a PublicKey");
        }

        return keyPair;
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM-512","ML_KEM_768","ML_KEM_1024"})
    protected void keyFactoryCreateFromEncoded(String Algorithm) throws Exception {

        pqcKeyFactory = KeyFactory.getInstance(Algorithm, getProviderName());
        KeyPair pqcKeyPair = generateKeyPair(Algorithm);
        
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(pqcKeyPair.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(
                pqcKeyPair.getPrivate().getEncoded());

        PublicKey pub =  pqcKeyFactory.generatePublic(x509Spec);
        PrivateKey priv =  pqcKeyFactory.generatePrivate(pkcs8Spec);


        assertArrayEquals(pub.getEncoded(),pqcKeyPair.getPublic().getEncoded(),"Public key does not match generated public key");
        assertArrayEquals(priv.getEncoded(),pqcKeyPair.getPrivate().getEncoded(),"Private key does not match generated public key");

    }
}

