/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplusfips;

import ibm.jceplus.junit.base.BaseTestJunit5;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(Lifecycle.PER_CLASS)
public class TestFIPSVerifyOnlyTest extends BaseTestJunit5 {

    @BeforeAll
    public void beforeAll() {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    @Test
    public void testFIPSDSAVerifyOnlyTest() {
        try {
            assertTrue(doVerify("DSA", "SHA256withDSA", 1024, "OpenJCEPlus", "OpenJCEPlusFIPS"));

        } catch (Exception e1) {
            System.out.println("Exception: " + e1.getMessage());
            assertTrue(false);
        }
    }

    @Test
    public void testFIPSECDSAVerifyOnlyTest() {
        try {
            assertTrue(doVerify("EC", "SHA256withECDSA", 192, "OpenJCEPlus", "OpenJCEPlusFIPS"));
        } catch (Exception e1) {
            System.out.println("Exception: " + e1.getMessage());
            assertTrue(false);
        }
    }

    @Test
    public void testFIPSRSAVerifyOnlyTest() {
        try {
            assertTrue(doVerify("RSA", "SHA256withRSA", 1024, "OpenJCEPlus", "OpenJCEPlusFIPS"));
        } catch (Exception e1) {
            System.out.println("Exception: " + e1.getMessage());
            assertTrue(false);
        }
    }

    private boolean doVerify(String keyAlg, String sigAlg, int keySize, String keygenProv,
            String testProv) {
        Signature signature1 = null;
        KeyFactory kf2;
        Signature signature2 = null;

        byte[] content = {(byte) 0x5F, (byte) 0x78, (byte) 0x4F, (byte) 0xC3, (byte) 0xE2,
                (byte) 0xE7, (byte) 0x65, (byte) 0xC0, (byte) 0x31, (byte) 0xF8, (byte) 0x97,
                (byte) 0x03, (byte) 0xDD, (byte) 0x71, (byte) 0x9A, (byte) 0xBD, (byte) 0xC5,
                (byte) 0x2B, (byte) 0xB1, (byte) 0x8E};

        try {
            KeyFactory.getInstance(keyAlg, keygenProv);
            kf2 = KeyFactory.getInstance(keyAlg, testProv);

            KeyPairGenerator dsaKeyPairGen = KeyPairGenerator.getInstance(keyAlg, keygenProv);
            dsaKeyPairGen.initialize(keySize);
            KeyPair dsaKeyPairX = dsaKeyPairGen.generateKeyPair();

            X509EncodedKeySpec x509SpecX = new X509EncodedKeySpec(
                    dsaKeyPairX.getPublic().getEncoded());

            PublicKey publicKey = kf2.generatePublic(x509SpecX);
            PrivateKey privateKey = dsaKeyPairX.getPrivate();

            signature1 = Signature.getInstance(sigAlg, keygenProv);
            signature2 = Signature.getInstance(sigAlg, testProv);
            signature1.initSign(privateKey);
            signature1.update(content);
            byte[] sigBytes = signature1.sign();

            //Verify with orignal public key

            // Verify the signature
            signature2.initVerify(publicKey);
            signature2.update(content);

            boolean signatureVerified = signature2.verify(sigBytes);

            return signatureVerified;

        } catch (Exception e1) {
            throw new RuntimeException(e1);
        }

    }

}
