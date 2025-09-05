/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.ProviderException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestECKeyPairGenerator extends BaseTestJunit5 {

    KeyPairGenerator kpg = null;
    KeyPairGenerator kpgc = null;

    @BeforeEach
    public void setUp() throws Exception {
        kpg = KeyPairGenerator.getInstance("EC", getProviderName());
        kpgc = KeyPairGenerator.getInstance("EC", getProviderName());
    }

    @Test
    public void testECKeyGen_IncorrectSize() throws Exception {
        try {
            doECKeyGen(255);
            throw new RuntimeException("Expected excepton for incorrect key size not thrown");
        } catch (ProviderException pe) {
            // expected
        }
    }

    @Test
    public void testECKeyGen_192() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS no longer supports P-192 key gen
            return;
        }
        doECKeyGen(192);
    }

    @Test
    public void testECKeyGen_256() throws Exception {
        doECKeyGen(256);
    }

    @Test
    public void testECKeyGen_384() throws Exception {
        doECKeyGen(384);

    }

    @Test
    public void testECKeyGen_521() throws Exception {
        doECKeyGen(521);
    }

    public void doECKeyGen(int keypairSize) throws Exception {
        kpg.initialize(keypairSize);
        KeyPair kp = kpg.generateKeyPair();

        assert (kp != null);

        assert (kp.getPublic() != null);
        assert (kp.getPrivate() != null);

        ECPublicKey ecpu = (ECPublicKey) kp.getPublic();
        ECPrivateKey ecpr = (ECPrivateKey) kp.getPrivate();

        assert (ecpu.getW() != null);
        assert (ecpr.getS() != null);

        //System.out.println("---- EC keypair for key size " + keypairSize + "  ----");
        //System.out.println("ECPublic (x,y): (" + ecpu.getW().getAffineX() + ", " + ecpu.getW().getAffineY() + ")");
        //System.out.println("ECPrivate: " + ecpr.getS());
    }

    public void compareEcParameterSpec(ECParameterSpec ecParameterSpecPub,
            ECParameterSpec ParameterSpecPriv) {

        ECPoint ecPointPub = ecParameterSpecPub.getGenerator();
        int cofactorPub = ecParameterSpecPub.getCofactor();
        BigInteger orderPub = ecParameterSpecPub.getOrder();
        EllipticCurve ecurvePub = ecParameterSpecPub.getCurve();

        ECPoint ecPointPriv = ecParameterSpecPub.getGenerator();
        int cofactorPriv = ecParameterSpecPub.getCofactor();
        BigInteger orderPriv = ecParameterSpecPub.getOrder();
        EllipticCurve ecurvePriv = ecParameterSpecPub.getCurve();

        assertTrue(orderPriv.compareTo(orderPub) == 0);
        assertTrue(cofactorPriv == cofactorPub);
        assertTrue(ecPointPriv.getAffineX().compareTo(ecPointPub.getAffineX()) == 0);
        assertTrue(ecPointPriv.getAffineY().compareTo(ecPointPub.getAffineY()) == 0);
        assertTrue(ecurvePriv.getA().compareTo(ecurvePub.getA()) == 0);
        assertTrue(ecurvePriv.getB().compareTo(ecurvePub.getB()) == 0);
        assertTrue(ecurvePriv.getField().getFieldSize() == ecurvePub.getField().getFieldSize());

    }

    @Test
    public void testECKeyGenCurves_secp192k1() throws Exception {
        generictestECKeyGenCurve("secp192k1");
        generictestECKeyGenCurve("1.3.132.0.31");
        generictestECKeyGenCurve("NIST P-192");

    }

    @Test
    public void testPrintECCurves() throws Exception {
        if (getProviderName().equalsIgnoreCase("OpenJCEPlus")) {

            generictestECKeyGenCurve("secp112r1");
            generictestECKeyGenCurve("1.3.132.0.6");

            generictestECKeyGenCurve("secp112r2");
            generictestECKeyGenCurve("1.3.132.0.7");

            generictestECKeyGenCurve("secp128r1");
            generictestECKeyGenCurve("1.3.132.0.28");

            generictestECKeyGenCurve("secp128r2");
            generictestECKeyGenCurve("1.3.132.0.29");


        }

        generictestECKeyGenCurve("secp160k1");
        generictestECKeyGenCurve("1.3.132.0.9");

        generictestECKeyGenCurve("secp160r1");
        generictestECKeyGenCurve("1.3.132.0.8");

        generictestECKeyGenCurve("secp160r2");
        generictestECKeyGenCurve("1.3.132.0.30");

        generictestECKeyGenCurve("secp192k1");
        generictestECKeyGenCurve("1.3.132.0.31");

        generictestECKeyGenCurve("secp192r1");
        generictestECKeyGenCurve("NIST P-192");

        generictestECKeyGenCurve("X9.62 prime192v1");
        generictestECKeyGenCurve("1.2.840.10045.3.1.1");

        generictestECKeyGenCurve("secp224k1");
        generictestECKeyGenCurve("1.3.132.0.32");

        generictestECKeyGenCurve("secp224r1");
        generictestECKeyGenCurve("NIST P-224");
        generictestECKeyGenCurve("1.3.132.0.33");

        generictestECKeyGenCurve("secp256k1");
        generictestECKeyGenCurve("1.3.132.0.10");

        generictestECKeyGenCurve("secp256r1");
        generictestECKeyGenCurve("NIST P-256");

        generictestECKeyGenCurve("X9.62 prime256v1");
        generictestECKeyGenCurve("1.2.840.10045.3.1.7");

        generictestECKeyGenCurve("secp384r1");
        generictestECKeyGenCurve("NIST P-384");
        generictestECKeyGenCurve("1.3.132.0.34");

        generictestECKeyGenCurve("secp521r1");
        generictestECKeyGenCurve("NIST P-521");
        generictestECKeyGenCurve("1.3.132.0.35");

        /* ANSI X9.62 prime curves */

        generictestECKeyGenCurve("X9.62 prime192v2");
        generictestECKeyGenCurve("1.2.840.10045.3.1.2");


        generictestECKeyGenCurve("X9.62 prime192v3");
        generictestECKeyGenCurve("1.2.840.10045.3.1.3");


        generictestECKeyGenCurve("X9.62 prime239v1");
        generictestECKeyGenCurve("1.2.840.10045.3.1.4");

        generictestECKeyGenCurve("X9.62 prime239v2");
        generictestECKeyGenCurve("1.2.840.10045.3.1.5");

        generictestECKeyGenCurve("X9.62 prime239v3");
        generictestECKeyGenCurve("1.2.840.10045.3.1.6");

        /* Brainpool curves */

        generictestECKeyGenCurve("brainpoolP160r1");
        generictestECKeyGenCurve("1.3.36.3.3.2.8.1.1.1");

        generictestECKeyGenCurve("brainpoolP192r1");
        generictestECKeyGenCurve("1.3.36.3.3.2.8.1.1.3");

        generictestECKeyGenCurve("brainpoolP224r1");
        generictestECKeyGenCurve("1.3.36.3.3.2.8.1.1.5");

        generictestECKeyGenCurve("brainpoolP256r1");
        generictestECKeyGenCurve("1.3.36.3.3.2.8.1.1.7");

        generictestECKeyGenCurve("brainpoolP320r1");
        generictestECKeyGenCurve("1.3.36.3.3.2.8.1.1.9");

        generictestECKeyGenCurve("brainpoolP384r1");
        generictestECKeyGenCurve("1.3.36.3.3.2.8.1.1.11");

        generictestECKeyGenCurve("brainpoolP512r1");
        generictestECKeyGenCurve("1.3.36.3.3.2.8.1.1.13");

    }

    @Test
    public void testUnsupportedCurveNames() throws Exception {
        try {
            generictestECKeyGenCurve("NIST P-1929");
            assertTrue(false);
        } catch (InvalidAlgorithmParameterException ex) {
            assertTrue(true);
        }
        try {
            generictestECKeyGenCurve("prime192-v1");
            assertTrue(false);
        } catch (InvalidAlgorithmParameterException ex) {
            // ex.printStackTrace();
            assertTrue(true);
        }

        boolean isDeveloperModePlatform = BaseUtils.getIsFIPSCertifiedPlatform();
        if (getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS") && isDeveloperModePlatform) {
            try {
                generictestECKeyGenCurve("secp112r1");
                assertTrue(false);
            } catch (InvalidAlgorithmParameterException | ProviderException ex) {
                assertTrue(true);
            }

            try {
                generictestECKeyGenCurve("1.3.132.0.6");
                assertTrue(false);
            } catch (InvalidAlgorithmParameterException | ProviderException ex) {
                assertTrue(true);
            }


            try {
                generictestECKeyGenCurve("secp112r2");
                assertTrue(false);
            } catch (InvalidAlgorithmParameterException | ProviderException ex) {
                assertTrue(true);
            }
            try {
                generictestECKeyGenCurve("1.3.132.0.7");
                assertTrue(false);
            } catch (InvalidAlgorithmParameterException | ProviderException ex) {
                assertTrue(true);
            }
            try {
                generictestECKeyGenCurve("secp128r1");
                assertTrue(false);
            } catch (InvalidAlgorithmParameterException | ProviderException ex) {
                assertTrue(true);
            }

            try {
                generictestECKeyGenCurve("1.3.132.0.28");
                assertTrue(false);
            } catch (InvalidAlgorithmParameterException | ProviderException ex) {
                assertTrue(true);
            }

            try {
                generictestECKeyGenCurve("secp128r2");
                assertTrue(false);
            } catch (InvalidAlgorithmParameterException | ProviderException ex) {
                assertTrue(true);
            }

            try {
                generictestECKeyGenCurve("1.3.132.0.29");
                assertTrue(false);
            } catch (InvalidAlgorithmParameterException | ProviderException ex) {
                assertTrue(true);
            }

            try {
                generictestECKeyGenCurve("1.3.132.0.29");
                assertTrue(false);
            } catch (InvalidAlgorithmParameterException | ProviderException ex) {
                assertTrue(true);
            }

        }

    }

    protected void generictestECKeyGenCurve(String curveName) throws Exception {
        // ECGenParameterSpec ecSpec = new ECGenParameterSpec ("secp192k1");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        kpgc.initialize(ecSpec);
        KeyPair kp = kpgc.generateKeyPair();

        assert (kp != null);

        assert (kp.getPublic() != null);
        assert (kp.getPrivate() != null);

        ECPublicKey ecpu = (ECPublicKey) kp.getPublic();
        ECPrivateKey ecpr = (ECPrivateKey) kp.getPrivate();

        assert (ecpu.getW() != null);
        assert (ecpr.getS() != null);

        //System.out.println("---- 192 test ----");
        //System.out.println("ECPublic (x,y): (" + ecpu.getW().getAffineX() + ", " + ecpu.getW().getAffineY() + ")");
        //System.out.println("ECPrivate: " + ecpr.getS());
    }
}
