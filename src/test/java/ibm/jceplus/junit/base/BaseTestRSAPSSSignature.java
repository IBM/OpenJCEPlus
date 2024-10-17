/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import ibm.jceplus.junit.base.certificateutils.CertAndKeyGen;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import sun.security.x509.X500Name;
import static org.junit.Assert.assertTrue;

public class BaseTestRSAPSSSignature extends BaseTestSignature {

    String IBM_ALG = "RSAPSS";
    String BC_ALG = "SHA1withRSAandMGF1";

    static final PSSParameterSpec specSHA256Salt20 = new PSSParameterSpec("SHA256", "MGF1",
            MGF1ParameterSpec.SHA256, 20, 1);
    static final String hexSHA256Salt20 = "302fa00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500";
    static final PSSParameterSpec specSHA256Salt40 = new PSSParameterSpec("SHA256", "MGF1",
            MGF1ParameterSpec.SHA256, 40, 1);
    static final String hexSHA256Salt40 = "3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020128";

    private static final byte[] content = {(byte) 0x5F, (byte) 0x78, (byte) 0x4F, (byte) 0xC3,
            (byte) 0xE2, (byte) 0xE7, (byte) 0x65, (byte) 0xC0, (byte) 0x31, (byte) 0xF8,
            (byte) 0x97, (byte) 0x03, (byte) 0xDD, (byte) 0x71, (byte) 0x9A, (byte) 0xBD,
            (byte) 0xC5, (byte) 0x2B, (byte) 0xB1, (byte) 0x8E};

    private static final byte[] content1 = {(byte) 0x5F, (byte) 0x78, (byte) 0x4F, (byte) 0xC3,
            (byte) 0xE2, (byte) 0xE7, (byte) 0x65, (byte) 0xC0, (byte) 0x31, (byte) 0xF8,
            (byte) 0x97, (byte) 0x03, (byte) 0xDD, (byte) 0x71, (byte) 0x9A, (byte) 0xBD,
            (byte) 0xC5, (byte) 0x2B, (byte) 0xB1, (byte) 0x8E, (byte) 0x5F, (byte) 0x78,
            (byte) 0x4F, (byte) 0xC3, (byte) 0xE2, (byte) 0xE7, (byte) 0x65, (byte) 0xC0,
            (byte) 0x31, (byte) 0xF8, (byte) 0x97, (byte) 0x03, (byte) 0xDD, (byte) 0x71,
            (byte) 0x9A, (byte) 0xBD, (byte) 0xC5, (byte) 0x2B, (byte) 0xB1};

    private static final byte[] oneByte = {(byte) 0x5F};
    private static byte[] elevenBytes = {(byte) 0x5F, (byte) 0x78, (byte) 0x4F, (byte) 0xC3,
            (byte) 0xE2, (byte) 0xE7, (byte) 0x65, (byte) 0xC0, (byte) 0x31, (byte) 0xF8,
            (byte) 0x97};

    private static final byte[] content3 = {(byte) 0x5F, (byte) 0x78, (byte) 0x4F, (byte) 0xC3,
            (byte) 0xE2, (byte) 0xE7, (byte) 0x65, (byte) 0xC0, (byte) 0x31, (byte) 0xF8,
            (byte) 0x97, (byte) 0x03, (byte) 0xDD, (byte) 0x71, (byte) 0x9A, (byte) 0xBD,
            (byte) 0xC5, (byte) 0x2B, (byte) 0xB1, (byte) 0x8E, (byte) 0x5F, (byte) 0x78,
            (byte) 0x4F, (byte) 0xC3, (byte) 0xE2, (byte) 0xE7, (byte) 0x65, (byte) 0xC0,
            (byte) 0x31, (byte) 0xF8, (byte) 0x97, (byte) 0x03, (byte) 0xDD, (byte) 0x71,
            (byte) 0x9A, (byte) 0xBD, (byte) 0xC5, (byte) 0x2B, (byte) 0xB1, (byte) 0x4F,
            (byte) 0xC3, (byte) 0xE2, (byte) 0xE7, (byte) 0x65, (byte) 0xC0, (byte) 0x31,
            (byte) 0xF8, (byte) 0x97, (byte) 0x03, (byte) 0xDD, (byte) 0x71, (byte) 0x9A,
            (byte) 0xBD, (byte) 0xC5, (byte) 0x2B, (byte) 0xB1, (byte) 0x8E, (byte) 0x5F,
            (byte) 0x78, (byte) 0x4F, (byte) 0xC3, (byte) 0xE2, (byte) 0xE7, (byte) 0x65,
            (byte) 0xC0, (byte) 0x31, (byte) 0xF8, (byte) 0x97, (byte) 0x03, (byte) 0xDD,
            (byte) 0x71, (byte) 0x9A, (byte) 0xBD, (byte) 0xC5, (byte) 0x2B, (byte) 0xB1,
            (byte) 0x4F, (byte) 0xC3, (byte) 0xE2, (byte) 0xE7, (byte) 0x65, (byte) 0xC0,
            (byte) 0x31, (byte) 0xF8, (byte) 0x97, (byte) 0x03, (byte) 0xDD, (byte) 0x71,
            (byte) 0x9A, (byte) 0xBD, (byte) 0xC5, (byte) 0x2B, (byte) 0xB1, (byte) 0x8E,
            (byte) 0x5F, (byte) 0x78, (byte) 0x4F, (byte) 0xC3, (byte) 0xE2, (byte) 0xE7,
            (byte) 0x65, (byte) 0xC0, (byte) 0x31, (byte) 0xF8, (byte) 0x97, (byte) 0x03,
            (byte) 0xDD, (byte) 0x71, (byte) 0x9A, (byte) 0xBD, (byte) 0xC5, (byte) 0x2B,
            (byte) 0xB1, (byte) 0x4F, (byte) 0xC3, (byte) 0xE2, (byte) 0xE7, (byte) 0x65,
            (byte) 0xC0, (byte) 0x31, (byte) 0xF8, (byte) 0x97, (byte) 0x03, (byte) 0xDD,
            (byte) 0x71, (byte) 0x9A, (byte) 0xBD, (byte) 0xC5, (byte) 0x2B, (byte) 0xB1,
            (byte) 0x8E, (byte) 0x5F, (byte) 0x78, (byte) 0x4F, (byte) 0xC3, (byte) 0xE2,
            (byte) 0xE7, (byte) 0x65, (byte) 0xC0, (byte) 0x31, (byte) 0xF8, (byte) 0x97,
            (byte) 0x03, (byte) 0xDD, (byte) 0x71, (byte) 0x9A, (byte) 0xBD, (byte) 0xC5,
            (byte) 0x2B, (byte) 0xB1};

    // Used by doGenKeyPair method
    final int EMPTY_PARAMS = 0;
    final int DEFAULT_PARAMS = 1;
    final int NONDEFAULT_PARAMS = 2;
    final int PARAMS_SALT40 = 3;
    static boolean printJunitTrace = false;


    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
        printJunitTrace = Boolean
                .valueOf(System.getProperty("com.ibm.jceplus.junit.printJunitTrace"));
    }

    @Test
    public void testRSASignatureWithPSS_SHA1() throws Exception {
        try {
            dotestSignature(content, IBM_ALG, 512, null, getProviderName());

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Change the keysize in steps of 32
     * Generate a key once and use it for multiple tests
     * @throws Exception
     */
    @Test
    public void testRSASignatureWithPSSBigMsgMultiKeySize() throws Exception {
        try {
            for (int i = 512; i < 4096;) {
                if (printJunitTrace)
                    System.out.println("keySize=" + i);
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(i, new java.security.SecureRandom());
                KeyPair keyPair = keyGen.genKeyPair();
                dotestSignature(content3, IBM_ALG, keyPair, null);
                dotestSignature(oneByte, IBM_ALG, keyPair, null);
                dotestSignature(content, IBM_ALG, keyPair, null);
                doSignatureBC2IBM(content, IBM_ALG, BC_ALG, keyPair, -1);
                doSignatureBC2IBM(content, IBM_ALG, BC_ALG, keyPair, 20);
                doSignatureBC2IBM(content, IBM_ALG, BC_ALG, keyPair, 40);
                dotestSignatureIBM2BC(content, IBM_ALG, BC_ALG, keyPair, -1);
                dotestSignatureIBM2BC(content, IBM_ALG, BC_ALG, keyPair, 20);
                dotestSignatureIBM2BC(content, IBM_ALG, BC_ALG, keyPair, 40);
                i = i + 32;
            }

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Verify a certificate generated and signed by BC
     * @throws Exception
     */
    @Test
    public void testCertBCtoIBM() throws Exception {

        // yesterday
        Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        // in 2 years
        Date validityEndDate = new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000);

        // GENERATE THE PUBLIC/PRIVATE RSA KEY PAIR
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(1024);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // GENERATE THE X509 CERTIFICATE
        org.bouncycastle.asn1.x500.X500Name issuer = new org.bouncycastle.asn1.x500.X500Name(new X500Principal("CN=John Doe").getName());

        SubjectPublicKeyInfo publicKeyInfo;

        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        publicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
                new RSAKeyParameters(false, rsaPublicKey.getModulus(), rsaPublicKey.getPublicExponent()));
        

        X509v1CertificateBuilder builder = new X509v1CertificateBuilder(issuer, BigInteger.ONE, validityBeginDate, validityEndDate,
                issuer, publicKeyInfo);

        ContentSigner signer = new JcaContentSignerBuilder(null).setProvider(new BouncyCastleProvider())
                .build(keyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);

        JcaX509CertificateConverter converter = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider());

        X509Certificate cert = converter.getCertificate(holder);

        byte[] derBytes0 = cert.getEncoded();
        if (printJunitTrace)
            System.out.println("signed certificate0=" + toHex(derBytes0));

        InputStream is0 = new ByteArrayInputStream(derBytes0);
        X509Certificate certificate0 = (X509Certificate) CertificateFactory
                .getInstance("X.509", getProviderName()).generateCertificate(is0);
        if (printJunitTrace)
            System.out.println(toHex(certificate0.getSigAlgParams()));

        if (printJunitTrace)
            System.out.println("Certificate0 parameters=" + toHex(certificate0.getSigAlgParams()));
        // certificate0.checkValidity();
        certificate0.verify(certificate0.getPublicKey());

    }

    /**
     * Change the message size. key size is fixed at 10. Used for timing the performance of
     * IBM vs BC
     * @throws Exception
     */
    @Test
    public void testRSASignatureWithPSSMultiByteSize_timed() throws Exception {
        try {
            for (int i = 1; i <= 100; i++) {
                byte[] dynMsg = new byte[i * 11];
                for (int j = 0; j < i; j++) {
                    System.arraycopy(elevenBytes, 0, dynMsg, j * 11, 11);
                }
                if (printJunitTrace)
                    System.out.println("msgSize=" + dynMsg.length);
                dotestSignature(dynMsg, IBM_ALG, 512, null, getProviderName());

            }

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Change the message size. key size is fixed at 10. Used for timing the performance of
     * IBM vs BC
     * @throws Exception
     */
    @Test
    public void testRSASignatureWithPSSMultiByteSize_timed_BC() throws Exception {
        try {
            for (int i = 1; i <= 100; i++) {
                byte[] dynMsg = new byte[i * 11];
                for (int j = 0; j < i; j++) {
                    System.arraycopy(elevenBytes, 0, dynMsg, j * 11, 11);
                }
                if (printJunitTrace)
                    System.out.println("msgSize=" + dynMsg.length);
                dotestSignature(dynMsg, BC_ALG, 512, null, "BC");

            }

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /** Test multiple raw messages generated by BC and verified by IBM
     * 
     * @throws Exception
     */
    @Test
    public void testRSASignatureWithPSSMultiByteSize_BC2IBM() throws Exception {
        try {
            for (int i = 1; i <= 301; i++) {
                byte[] dynMsg = new byte[i * 11];
                for (int j = 0; j < i; j++) {
                    System.arraycopy(elevenBytes, 0, dynMsg, j * 11, 11);
                }
                if (printJunitTrace)
                    System.out.println("msgSize=" + dynMsg.length);
                dotestSignatureBC2IBM(dynMsg, IBM_ALG, BC_ALG, 512, -1);
                dotestSignatureBC2IBM(dynMsg, IBM_ALG, BC_ALG, 512, 20);
                dotestSignatureBC2IBM(dynMsg, IBM_ALG, BC_ALG, 512, 40);

            }

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /** Test multiple raw messages generated by IBM and verified by BC
     * 
     * @throws Exception
     */
    @Test
    public void testRSASignatureWithPSSMultiByteSize_IBM2BC2() throws Exception {
        try {
            for (int i = 1; i <= 301; i++) {
                byte[] dynMsg = new byte[i * 11];
                for (int j = 0; j < i; j++) {
                    System.arraycopy(elevenBytes, 0, dynMsg, j * 11, 11);
                }
                if (printJunitTrace)
                    System.out.println("msgSize=" + dynMsg.length);
                doSignatureIBM2BC(dynMsg, IBM_ALG, BC_ALG, 512, 20);
                doSignatureIBM2BC(dynMsg, IBM_ALG, BC_ALG, 512, 40);
                doSignatureIBM2BC(dynMsg, IBM_ALG, BC_ALG, 512, -1);

            }

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /** 
     * Test after setting parameters
     * @throws Exception
     */
    @Test
    public void testRSASignatureWithPSSParameterSpec() throws Exception {
        try {
            dotestSignaturePSSParameterSpec(content1, IBM_ALG, 512);

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * SHA256
     * @throws Exception
     */
    @Test
    public void testRSASignatureSHA256() throws Exception {

        try {
            PSSParameterSpec pssParameter = specSHA256Salt20;
            dotestSignature(content, IBM_ALG, 2048, pssParameter, getProviderName());

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * SHA512
     * @throws Exception
     */
    @Test
    public void testRSASignatureSHA512() throws Exception {

        PSSParameterSpec pssParameter = new PSSParameterSpec("SHA512", "MGF1",
                MGF1ParameterSpec.SHA512, 20, 1);
        try {
            dotestSignature(content, IBM_ALG, 2048, pssParameter, getProviderName());

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * SHA512/224
     * @throws Exception
     */
    @Test
    public void testRSASignatureSHA512_224() throws Exception {

        PSSParameterSpec pssParameter = new PSSParameterSpec("SHA512/224", "MGF1",
                MGF1ParameterSpec.SHA512_224, 20, 1);
        try {
            dotestSignature(content, IBM_ALG, 2048, pssParameter, getProviderName());

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * SHA512/256
     * @throws Exception
     */
    @Test
    public void testRSASignatureSHA512_256() throws Exception {

        PSSParameterSpec pssParameter = new PSSParameterSpec("SHA512/256", "MGF1",
                MGF1ParameterSpec.SHA512_256, 20, 1);
        try {
            dotestSignature(content, IBM_ALG, 2048, pssParameter, getProviderName());

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * SHA384
     * @throws Exception
     */
    @Test
    public void testRSASignatureSHA384() throws Exception {
        try {
            PSSParameterSpec pssParameter = new PSSParameterSpec("SHA384", "MGF1",
                    MGF1ParameterSpec.SHA384, 20, 1);
            dotestSignature(content, IBM_ALG, 2048, pssParameter, getProviderName());

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * SHA255 - test one byte
     */
    @Test
    public void testRSASignatureSHA256OneByte() throws Exception {
        try {
            PSSParameterSpec pssParameterSpec = specSHA256Salt40;
            dotestSignaturePSSParameterSpec(oneByte, IBM_ALG, 2048, pssParameterSpec);

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Bouncy Castle to IBM
     * @throws Exception
     */
    @Test
    public void testRSASignatureSHA1_BC2IBM() throws Exception {
        try {
            dotestSignatureBC2IBM(oneByte, IBM_ALG, BC_ALG, 512, -1);
            dotestSignatureBC2IBM(oneByte, IBM_ALG, BC_ALG, 512, 20);
            dotestSignatureBC2IBM(oneByte, IBM_ALG, BC_ALG, 512, 40);
            dotestSignatureBC2IBM(oneByte, IBM_ALG, BC_ALG, 512, 60);

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * IBM to BC
     * @throws Exception
     */
    @Test
    public void testRSASignatureSHA1_IBM2BC() throws Exception {
        try {
            doSignatureIBM2BC(oneByte, IBM_ALG, BC_ALG, 512, -1);

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * 0 salt length
     * @throws Exception
     */
    @Test
    public void testRSASignatureSHA1_IBM2BC_0salt() throws Exception {
        try {
            doSignatureIBM2BC(oneByte, IBM_ALG, BC_ALG, 512, 0);

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Helper method
     * @param content
     * @param algorithm
     * @param keySize
     * @param pssParameterSpec
     * @param jceprovider
     * @throws Exception
     */
    protected void dotestSignature(byte[] content, String algorithm, int keySize,
            PSSParameterSpec pssParameterSpec, String jceprovider) throws Exception {

        // Generate Signature

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize, new java.security.SecureRandom());
        KeyPair keyPair = keyGen.genKeyPair();

        Signature sig = Signature.getInstance(algorithm, jceprovider);
        if (pssParameterSpec != null) {
            sig.setParameter(pssParameterSpec);
            AlgorithmParameters algParams = sig.getParameters();
            algParams.getParameterSpec(PSSParameterSpec.class);
            if (printJunitTrace)
                System.out.println("parameters=" + algParams.toString());
        }

        AlgorithmParameters algParams = sig.getParameters();
        algParams.getParameterSpec(PSSParameterSpec.class);
        if (printJunitTrace)
            System.out.println("parameters=" + algParams.toString());
        sig.initSign(keyPair.getPrivate());
        sig.update(content);
        byte[] sigBytes = sig.sign();

        // Verify the signature
        sig.initVerify(keyPair.getPublic());
        sig.update(content);

        // Check Signature
        // Signature verifySig = Signature.getInstance("SHA1withRSA/PSS",
        // getProviderName());
        // verifySig.initVerify(cert);
        // verifySig.update(content);
        boolean signatureVerified = sig.verify(sigBytes);

        assertTrue("signature is invalid!!", signatureVerified);
    }

    /**
     * Helper method
     * @param content
     * @param algorithm
     * @param keyPair
     * @param pssParameterSpec
     * @throws Exception
     */

    protected void dotestSignature(byte[] content, String algorithm, KeyPair keyPair,
            PSSParameterSpec pssParameterSpec) throws Exception {

        // Generate Signature

        // KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // keyGen.initialize(keySize, new java.security.SecureRandom());
        // KeyPair keyPair = keyGen.genKeyPair();

        Signature sig = Signature.getInstance(algorithm, getProviderName());
        if (pssParameterSpec != null) {
            sig.setParameter(pssParameterSpec);
        }
        sig.initSign(keyPair.getPrivate());
        sig.update(content);
        byte[] sigBytes = sig.sign();

        // Verify the signature
        sig.initVerify(keyPair.getPublic());
        sig.update(content);

        // Check Signature
        // Signature verifySig = Signature.getInstance("SHA1withRSA/PSS",
        // getProviderName());
        // verifySig.initVerify(cert);
        // verifySig.update(content);
        boolean signatureVerified = sig.verify(sigBytes);

        assertTrue("signature is invalid!!", signatureVerified);
    }

    /** 
     * Helper method
     * @param content
     * @param ibmalgorithm
     * @param bcalgorithm
     * @param keySize
     * @param saltSize
     * @throws Exception
     */

    protected void dotestSignatureBC2IBM(byte[] content, String ibmalgorithm, String bcalgorithm,
            int keySize, int saltSize) throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize, new java.security.SecureRandom());
        KeyPair keyPair = keyGen.genKeyPair();

        BC2IBM(content, ibmalgorithm, bcalgorithm, keyPair, saltSize);
    }

    protected void doSignatureBC2IBM(byte[] content, String ibmalgorithm, String bcalgorithm,
            KeyPair keyPair, int saltSize) throws Exception {

        BC2IBM(content, ibmalgorithm, bcalgorithm, keyPair, saltSize);
    }

    /**
     * Helper method to do the BC to IBM
     * @param plaintext
     * @param ibmalgorithm
     * @param bcalgorithm
     * @param keyPair
     * @param saltSize
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    void BC2IBM(byte[] plaintext, String ibmalgorithm, String bcalgorithm, KeyPair keyPair,
            int saltSize) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeyException, SignatureException {

        // Signature sig = Signature.getInstance(algorithm, getProviderName());
        Signature sig = Signature.getInstance(bcalgorithm, "BC");
        AlgorithmParameters algParams = sig.getParameters();
        try {
            algParams.getParameterSpec(PSSParameterSpec.class);
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        if (printJunitTrace)
            System.out.println("parameters=" + algParams.toString());
        sig.initSign(keyPair.getPrivate());
        sig.update(plaintext);
        byte[] sigBytes = sig.sign();

        Signature sig1 = Signature.getInstance(ibmalgorithm, getProviderName());
        // Verify the signature
        sig1.initVerify(keyPair.getPublic());
        sig1.update(plaintext);

        boolean signatureVerified = sig1.verify(sigBytes);
        if (printJunitTrace)
            System.out.println("Inter-op test " + signatureVerified);

        assertTrue("signature is invalid!!", signatureVerified);
    }

    /**
     * Helper to do IBM to BC
     * @param content
     * @param ibmalgorithm
     * @param bcalgorithm
     * @param keySize
     * @param saltsize
     * @throws Exception
     */
    protected void doSignatureIBM2BC(byte[] content, String ibmalgorithm, String bcalgorithm,
            int keySize, int saltsize) throws Exception {

        if (printJunitTrace)
            System.out.println("testSignatureIBM2BC");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize, new java.security.SecureRandom());
        KeyPair keyPair = keyGen.genKeyPair();

        IBM2BC(content, ibmalgorithm, bcalgorithm, keyPair, saltsize);

    }

    /** 
     * helper method
     * 
     * @param content
     * @param ibmalgorithm
     * @param bcalgorithm
     * @param keyPair
     * @param saltsize
     * @throws Exception
     */

    protected void dotestSignatureIBM2BC(byte[] content, String ibmalgorithm, String bcalgorithm,
            KeyPair keyPair, int saltsize) throws Exception {

        if (printJunitTrace)
            System.out.println("testSignatureIBM2BC");

        IBM2BC(content, ibmalgorithm, bcalgorithm, keyPair, saltsize);

    }

    /** 
     * Helper method
     * @param content
     * @param ibmalgorithm
     * @param bcalgorithm
     * @param keyPair
     * @param saltsize
     * @throws Exception
     */
    void IBM2BC(byte[] content, String ibmalgorithm, String bcalgorithm, KeyPair keyPair,
            int saltsize) throws Exception {

        PSSParameterSpec pssParameterSpec = null;

        // Generate Signature
        if (saltsize != -1) {
            pssParameterSpec = new PSSParameterSpec("SHA-1", "MGF1",
                    MGF1ParameterSpec.SHA1, saltsize, 1);;
        }

        // Signature sig = Signature.getInstance(algorithm, getProviderName());
        Signature sig = Signature.getInstance(bcalgorithm, "BC");
        if (pssParameterSpec != null) {
            sig.setParameter(pssParameterSpec);
        }
        AlgorithmParameters algParams = sig.getParameters();
        try {
            algParams.getParameterSpec(PSSParameterSpec.class);
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        if (printJunitTrace)
            System.out.println("parameters=" + algParams.toString());
        sig.initSign(keyPair.getPrivate());
        sig.update(content);
        byte[] sigBytes = sig.sign();

        Signature sig1 = Signature.getInstance(ibmalgorithm, getProviderName());
        if (pssParameterSpec != null) {
            sig1.setParameter(pssParameterSpec);
        }
        // Verify the signature
        sig1.initVerify(keyPair.getPublic());
        sig1.update(content);

        boolean signatureVerified = sig1.verify(sigBytes);
        if (printJunitTrace)
            System.out.println("Inter-op test " + signatureVerified);

        assertTrue("signature is invalid!!", signatureVerified);
    }

    /** 
     * Helper method
     * @param content
     * @param algorithm
     * @param keySize
     * @throws Exception
     */

    protected void dotestSignaturePSSParameterSpec(byte[] content, String algorithm, int keySize)
            throws Exception {
        if (printJunitTrace)
            System.out.println("testSignaturePSSParameterSpec");

        // Generate Signature

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize, new java.security.SecureRandom());
        KeyPair keyPair = keyGen.genKeyPair();

        Signature sig = Signature.getInstance(algorithm, getProviderName());
        // Set salt length
        PSSParameterSpec pss = new PSSParameterSpec("SHA-1", "MGF1",
                MGF1ParameterSpec.SHA1, 20, 1);
        sig.setParameter(pss);
        sig.initSign(keyPair.getPrivate());
        sig.update(content);
        byte[] sigBytes = sig.sign();

        // Verify the signature
        sig.initVerify(keyPair.getPublic());
        sig.update(content);

        boolean signatureVerified = sig.verify(sigBytes);

        assertTrue("signature is invalid!!", signatureVerified);
    }

    /**
     * Helper method
     * @param content
     * @param algorithm
     * @param keySize
     * @param pssParameterSpec
     * @throws Exception
     */
    protected void dotestSignaturePSSParameterSpec(byte[] content, String algorithm, int keySize,
            PSSParameterSpec pssParameterSpec) throws Exception {
        if (printJunitTrace)
            System.out.println("testSignaturePSSParameterSpec algorithm= " + algorithm + " keysize="
                    + keySize);

        // Generate Signature

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize, new java.security.SecureRandom());
        KeyPair keyPair = keyGen.genKeyPair();

        Signature sig = Signature.getInstance(algorithm, getProviderName());
        // Set salt length
        if (pssParameterSpec != null) {
            sig.setParameter(pssParameterSpec);
        }
        sig.initSign(keyPair.getPrivate());
        sig.update(content);
        byte[] sigBytes = sig.sign();

        // Verify the signature
        sig.initVerify(keyPair.getPublic());
        sig.update(content);

        boolean signatureVerified = sig.verify(sigBytes);

        assertTrue("signature is invalid!!", signatureVerified);
    }

    /**
     * Empty parameters
     * @throws Exception
     */
    @Test
    public void testCertSelfSignVerifyEmptyParams() throws Exception {

        String alias = "TestRSAPSS";
        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
        String keyAlgName = "RSA";
        int keysize = 1024;
        String sigAlgName = "RSAPSS";

        doGenKeyPair(alias, dname, keyAlgName, keysize, sigAlgName, EMPTY_PARAMS);

    }

    /**
     * IBM to BC empty params
     * @throws Exception
     */
    @Test
    public void testCertIBM2BCEmptyParams() throws Exception {

        String alias = "TestRSAPSS";
        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
        String keyAlgName = "RSA";
        int keysize = 1024;
        String sigAlgName = "RSAPSS";

        doGenKeyPairBC(alias, dname, keyAlgName, keysize, sigAlgName, EMPTY_PARAMS);

    }

    /**
     * All the 4 parameters are non default
     * @throws Exception
     */
    @Test
    public void testCertIBM2BCNonDefaultParams() throws Exception {

        String alias = "TestRSAPSS";
        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
        String keyAlgName = "RSA";
        int keysize = 1024;
        String sigAlgName = "RSAPSS";

        doGenKeyPairBC(alias, dname, keyAlgName, keysize, sigAlgName, NONDEFAULT_PARAMS);

    }

    /**
     * All parameters except salt are default
     * @throws Exception
     */
    @Test
    public void testCertIBM2BCParamsSalt40() throws Exception {

        String alias = "TestRSAPSS";
        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
        String keyAlgName = "RSA";
        int keysize = 1024;
        String sigAlgName = "RSAPSS";

        doGenKeyPairBC(alias, dname, keyAlgName, keysize, sigAlgName, PARAMS_SALT40);

    }

    /**
     * BC to IBM all default parameters
     * @throws Exception
     */
    @Test
    public void testCertIBM2BCDefaultParams() throws Exception {

        String alias = "TestRSAPSS";
        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
        String keyAlgName = "RSA";
        int keysize = 1024;
        String sigAlgName = "RSAPSS";

        doGenKeyPairBC(alias, dname, keyAlgName, keysize, sigAlgName, DEFAULT_PARAMS);

    }

    /**
     * Default parameters
     * @throws Exception
     */
    @Test
    public void testCertSelfSignVerifyDefaultParams() throws Exception {

        String alias = "TestRSAPSS";
        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
        String keyAlgName = "RSA";
        String sigAlgName = "RSAPSS";

        doGenKeyPair(alias, dname, keyAlgName, 512, sigAlgName, DEFAULT_PARAMS);
        doGenKeyPair(alias, dname, keyAlgName, 1024, sigAlgName, DEFAULT_PARAMS);
        doGenKeyPair(alias, dname, keyAlgName, 2048, sigAlgName, DEFAULT_PARAMS);

    }

    /**
     * Non default parameters
     * @throws Exception
     */
    @Test
    public void testCertSelfSignVerifyNonDefaultParams() throws Exception {

        String alias = "TestRSAPSS";
        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
        String keyAlgName = "RSA";
        String sigAlgName = "RSAPSS";

        doGenKeyPair(alias, dname, keyAlgName, 512, sigAlgName, NONDEFAULT_PARAMS);
        doGenKeyPair(alias, dname, keyAlgName, 1024, sigAlgName, NONDEFAULT_PARAMS);
        doGenKeyPair(alias, dname, keyAlgName, 2048, sigAlgName, NONDEFAULT_PARAMS);

    }

    /**
     * Non RSAPSS cert to make sure other certs are not broken by RSA-PSS
     */
    @Test
    public void testCertNonPSS() throws Exception {

        String alias = "TestNonRSAPSS";
        String dname = "CN=TestNonRSAPSS,OU=Tivoli,O=IBM,C=US";
        String keyAlgName = "RSA";
        int keysize = 1024;
        //String sigAlgName = "SHA1WithRSA";

        doGenKeyPair(alias, dname, keyAlgName, keysize, "SHA1WithRSA", EMPTY_PARAMS);
        doGenKeyPair(alias, dname, keyAlgName, keysize, "SHA2WithRSA", EMPTY_PARAMS);
    }

    /**
     * only the Salt is non default
     * @throws Exception
     */
    @Test
    public void testCertSelfSignDefaultParamsExceptSalt() throws Exception {

        String alias = "TestRSAPSS";
        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
        String keyAlgName = "RSA";
        String sigAlgName = "RSAPSS";

        doGenKeyPair(alias, dname, keyAlgName, 512, sigAlgName, PARAMS_SALT40);
        doGenKeyPair(alias, dname, keyAlgName, 1024, sigAlgName, PARAMS_SALT40);
        doGenKeyPair(alias, dname, keyAlgName, 2048, sigAlgName, PARAMS_SALT40);

    }

    /**
     * IBM to BC
     * @throws Exception
     */
    @Test
    public void testCertSelfSignDefaultParamsExceptSaltBC() throws Exception {

        String alias = "TestRSAPSS";
        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
        String keyAlgName = "RSA";
        String sigAlgName = "RSAPSS";

        doGenKeyPairBC(alias, dname, keyAlgName, 512, sigAlgName, PARAMS_SALT40);
        doGenKeyPairBC(alias, dname, keyAlgName, 1024, sigAlgName, PARAMS_SALT40);
        doGenKeyPairBC(alias, dname, keyAlgName, 2048, sigAlgName, PARAMS_SALT40);

    }

    /**
     * Creates a new key pair and self-signed certificate.
     */
    private void doGenKeyPair(String alias, String dname, String keyAlgName, int keysize,
            String sigAlgName, int paramsType) throws Exception {

        int validity = 365;
        if (keysize == -1) {
            if ("EC".equalsIgnoreCase(keyAlgName)) {
                keysize = 256;
            } else {
                keysize = 2048;
            }
        }

        if (sigAlgName == null) {
            if (keyAlgName.equalsIgnoreCase("DSA")) {
                sigAlgName = "SHA256WithDSA";
            } else if (keyAlgName.equalsIgnoreCase("RSA")) {
                sigAlgName = "SHA256WithRSA";
            } else if (keyAlgName.equalsIgnoreCase("EC")) {
                sigAlgName = "SHA256withECDSA";
            } else {
                throw new Exception("Cannot derive signature algorithm");
            }
        } else {
            if (keyAlgName.equalsIgnoreCase("DSA")) {
                String sigAlgNameLower = sigAlgName.toLowerCase();
                if (sigAlgNameLower.indexOf("rsa") != -1) {
                    throw new Exception("Key algorithm and signature algorithm mismatch");
                }
            } else if (keyAlgName.equalsIgnoreCase("RSA")) {
                String sigAlgNameLower = sigAlgName.toLowerCase();
                if (sigAlgNameLower.indexOf("dsa") != -1) {
                    throw new Exception("Key algorithm and signature algorithm mismatch");
                }
            }
        }
        CertAndKeyGen keypair = new CertAndKeyGen(keyAlgName, sigAlgName, getProviderName());

        // If DN is provided, parse it. Otherwise, prompt the user for it.
        X500Name x500Name = new X500Name(dname);

        //Object[] source = {new Integer(keysize), keyAlgName, sigAlgName, x500Name};
        //System.err
        //        .println("Generating keysize bit keyAlgName key pair and self-signed certificate (sigAlgName)\n\tfor: x500Name"
        //                + source);

        switch (paramsType) {

            case EMPTY_PARAMS:

                // Empty Parameters

                keypair.generate(keysize);
                X509Certificate[] chain0 = new X509Certificate[1];
                chain0[0] = keypair.getSelfCert(x500Name, (long) validity * 24 * 60 * 60);

                byte[] derBytes0 = chain0[0].getEncoded();
                if (printJunitTrace)
                    System.out.println("signed certificate0=" + toHex(derBytes0));

                InputStream is0 = new ByteArrayInputStream(derBytes0);
                X509Certificate certificate0 = (X509Certificate) CertificateFactory
                        .getInstance("X.509").generateCertificate(is0);
                assertTrue(certificate0.getSigAlgParams() == null);
                if (printJunitTrace)
                    System.out.println(
                            "Certificate0 parameters=" + toHex(certificate0.getSigAlgParams()));
                certificate0.checkValidity();
                certificate0.verify(certificate0.getPublicKey());
                break;

            case DEFAULT_PARAMS:
                // All defaultParams
                PSSParameterSpec pssParameterSpec1 = new PSSParameterSpec("SHA-1", "MGF1",
                        MGF1ParameterSpec.SHA1, 20, 1);

                keypair.generate(keysize);

                X509Certificate[] chain1 = new X509Certificate[1];
                chain1[0] = keypair.getSelfCert(x500Name, (long) validity * 24 * 60 * 60,
                        pssParameterSpec1);

                byte[] derBytes1 = chain1[0].getEncoded();
                if (printJunitTrace)
                    System.out.println("signed certificate1=" + toHex(derBytes1));

                InputStream is1 = new ByteArrayInputStream(derBytes1);
                X509Certificate certificate1 = (X509Certificate) CertificateFactory
                        .getInstance("X.509").generateCertificate(is1);
                if (printJunitTrace)
                    System.out.println(
                            "Certificate1 parameters=" + toHex(certificate1.getSigAlgParams()));

                //X509CertImpl certImpl = (X509CertImpl) certificate1;

                certificate1.verify(certificate1.getPublicKey(), (String) null);

                //            certImpl.verify(certificate1.getPublicKey(), null,
                //                    certificate1.getSigAlgParams());
                certificate1.checkValidity();
                assertTrue(toHex(certificate1.getSigAlgParams()).equals("3000"));
                // Hex string was verified manually using asnDecoder utility
                //assertTrue(toHex(certificate1.getSigAlgParams())
                //        .equals("3027a00b300906052b0e03021a0500a118301606092a864886f70d010108300906052b0e03021a0500"));
                break;

            case NONDEFAULT_PARAMS:
                // Non Default parameters
                PSSParameterSpec pssParameterSpec2 = specSHA256Salt20;

                keypair.generate(keysize);
                X509Certificate[] chain2 = new X509Certificate[1];

                chain2[0] = keypair.getSelfCert(x500Name, (long) validity * 24 * 60 * 60,
                        (AlgorithmParameterSpec) pssParameterSpec2);

                byte[] derBytes2 = chain2[0].getEncoded();
                if (printJunitTrace)
                    System.out.println("signed certificate2=" + toHex(derBytes2));

                InputStream is2 = new ByteArrayInputStream(derBytes2);
                X509Certificate certificate2 = (X509Certificate) CertificateFactory
                        .getInstance("X.509").generateCertificate(is2);
                if (printJunitTrace)
                    System.out.println(
                            "Certificate2 parameters=" + toHex(certificate2.getSigAlgParams()));
                certificate2.verify(certificate2.getPublicKey(), (String) null);
                //X509CertImpl certImpl2 = (X509CertImpl) certificate2;

                //certImpl2.verify(certificate2.getPublicKey(), null,
                //        certificate2.getSigAlgParams());

                certificate2.checkValidity();
                String algString = toHex(certificate2.getSigAlgParams());
                assertTrue(algString.equals(hexSHA256Salt20));
                break;

            case PARAMS_SALT40:
                PSSParameterSpec pssParameterSpec3 = new PSSParameterSpec("SHA-1", "MGF1",
                        MGF1ParameterSpec.SHA1, 40, 1);
                keypair.generate(keysize);
                X509Certificate[] chain3 = new X509Certificate[1];

                chain3[0] = keypair.getSelfCert(x500Name, (long) validity * 24 * 60 * 60,
                        (AlgorithmParameterSpec) pssParameterSpec3);

                byte[] derBytes3 = chain3[0].getEncoded();
                if (printJunitTrace)
                    System.out.println("signed certificate3=" + toHex(derBytes3));

                InputStream is3 = new ByteArrayInputStream(derBytes3);
                X509Certificate certificate3 = (X509Certificate) CertificateFactory
                        .getInstance("X.509").generateCertificate(is3);
                if (printJunitTrace)
                    System.out.println(
                            "Certificate3 parameters=" + toHex(certificate3.getSigAlgParams()));
                certificate3.checkValidity();

                certificate3.verify(certificate3.getPublicKey(), (String) null);
                //            X509CertImpl certImpl3 = (X509CertImpl) certificate3;
                //            certImpl3.verify(certificate3.getPublicKey(), null,
                //                    certificate3.getSigAlgParams());
                assertTrue(toHex(certificate3.getSigAlgParams()).equals("3005a203020128"));
                break;

            default:
                assertTrue(false);
        }

    }

    /**
     * Creates a new key pair and self-signed certificate for Bouncy Castle
     */
    private void doGenKeyPairBC(String alias, String dname, String keyAlgName, int keysize,
            String sigAlgName, int paramsType) throws Exception {

        int validity = 365;
        if (keysize == -1) {
            if ("EC".equalsIgnoreCase(keyAlgName)) {
                keysize = 256;
            } else {
                keysize = 2048;
            }
        }

        if (sigAlgName == null) {
            if (keyAlgName.equalsIgnoreCase("DSA")) {
                sigAlgName = "SHA256WithDSA";
            } else if (keyAlgName.equalsIgnoreCase("RSA")) {
                sigAlgName = "SHA256WithRSA";
            } else if (keyAlgName.equalsIgnoreCase("EC")) {
                sigAlgName = "SHA256withECDSA";
            } else {
                throw new Exception("Cannot derive signature algorithm");
            }
        } else {
            if (keyAlgName.equalsIgnoreCase("DSA")) {
                String sigAlgNameLower = sigAlgName.toLowerCase();
                if (sigAlgNameLower.indexOf("rsa") != -1) {
                    throw new Exception("Key algorithm and signature algorithm mismatch");
                }
            } else if (keyAlgName.equalsIgnoreCase("RSA")) {
                String sigAlgNameLower = sigAlgName.toLowerCase();
                if (sigAlgNameLower.indexOf("dsa") != -1) {
                    throw new Exception("Key algorithm and signature algorithm mismatch");
                }
            }
        }
        CertAndKeyGen keypair = new CertAndKeyGen(keyAlgName, sigAlgName, getProviderName());

        KeyPairGenerator.getInstance("RSA", "BC");

        // If DN is provided, parse it. Otherwise, prompt the user for it.
        X500Name x500Name = new X500Name(dname);

        //Object[] source = {new Integer(keysize), keyAlgName, sigAlgName, x500Name};
        //        System.err
        //                .println("Generating keysize bit keyAlgName key pair and self-signed certificate (sigAlgName)\n\tfor: x500Name"
        //                        + source);

        switch (paramsType) {

            case EMPTY_PARAMS:

                // Empty Parameters

                keypair.generate(keysize);
                X509Certificate[] chain0 = new X509Certificate[1];
                chain0[0] = keypair.getSelfCert(x500Name, (long) validity * 24 * 60 * 60);

                byte[] derBytes0 = chain0[0].getEncoded();
                if (printJunitTrace)
                    System.out.println("signed certificate0=" + toHex(derBytes0));

                InputStream is0 = new ByteArrayInputStream(derBytes0);
                X509Certificate certificate0 = (X509Certificate) CertificateFactory
                        .getInstance("X.509").generateCertificate(is0);
                assertTrue(certificate0.getSigAlgParams() == null);
                if (printJunitTrace)
                    System.out.println(
                            "Certificate0 parameters=" + toHex(certificate0.getSigAlgParams()));
                certificate0.checkValidity();
                // X509Certificate certBC = getPemCert(derBytes3);
                // certBC.verify(certBC.getPublicKey(), "BC");
                // String certInPEMFormat = convertToPEMFormat(certificate0);
                java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
                        .getInstance("X.509", "BC");
                InputStream istream = new ByteArrayInputStream(derBytes0);
                java.security.cert.Certificate cert = cf.generateCertificate(istream);
                assertTrue(cert != null);
                cert.verify(cert.getPublicKey());
                assertTrue(Arrays.equals(cert.getEncoded(), certificate0.getEncoded()));

                break;

            case DEFAULT_PARAMS:
                // All defaultParams
                PSSParameterSpec pssParameterSpec1 = new PSSParameterSpec("SHA-1", "MGF1",
                        MGF1ParameterSpec.SHA1, 20, 1);

                keypair.generate(keysize);

                X509Certificate[] chain1 = new X509Certificate[1];
                chain1[0] = keypair.getSelfCert(x500Name, (long) validity * 24 * 60 * 60,
                        pssParameterSpec1);

                byte[] derBytes1 = chain1[0].getEncoded();
                if (printJunitTrace)
                    System.out.println("signed certificate1=" + toHex(derBytes1));

                InputStream is1 = new ByteArrayInputStream(derBytes1);
                X509Certificate certificate1 = (X509Certificate) CertificateFactory
                        .getInstance("X.509").generateCertificate(is1);
                if (printJunitTrace)
                    System.out.println(
                            "Certificate1 parameters=" + toHex(certificate1.getSigAlgParams()));

                certificate1.verify(certificate1.getPublicKey(), (String) null);

                //            certImpl.verify(certificate1.getPublicKey(), (Provider) null,
                //                    certificate1.getSigAlgParams());
                certificate1.checkValidity();
                // Hex string was verified manually using asnDecoder utility
                //assertTrue(toHex(certificate1.getSigAlgParams())
                //            .equals("3027a00b300906052b0e03021a0500a118301606092a864886f70d010108300906052b0e03021a0500"));

                java.security.cert.CertificateFactory cf1 = java.security.cert.CertificateFactory
                        .getInstance("X.509", "BC");
                InputStream istream1 = new ByteArrayInputStream(derBytes1);
                java.security.cert.Certificate cert1 = cf1.generateCertificate(istream1);
                assertTrue(cert1 != null);
                cert1.verify(cert1.getPublicKey());
                assertTrue(Arrays.equals(cert1.getEncoded(), certificate1.getEncoded()));
                break;

            case NONDEFAULT_PARAMS:
                // Non Default parameters
                PSSParameterSpec pssParameterSpec2 = specSHA256Salt40;

                keypair.generate(keysize);
                X509Certificate[] chain2 = new X509Certificate[1];

                chain2[0] = keypair.getSelfCert(x500Name, (long) validity * 24 * 60 * 60,
                        (AlgorithmParameterSpec) pssParameterSpec2);

                byte[] derBytes2 = chain2[0].getEncoded();
                if (printJunitTrace)
                    System.out.println("signed certificate2=" + toHex(derBytes2));

                InputStream is2 = new ByteArrayInputStream(derBytes2);
                X509Certificate certificate2 = (X509Certificate) CertificateFactory
                        .getInstance("X.509").generateCertificate(is2);
                if (printJunitTrace)
                    System.out.println(
                            "Certificate2 parameters=" + toHex(certificate2.getSigAlgParams()));
                certificate2.verify(certificate2.getPublicKey(), (String) null);
                //            X509CertImpl certImpl2 = (X509CertImpl) certificate2;

                //            certImpl2.verify(certificate2.getPublicKey(), null,
                //                    certificate2.getSigAlgParams());

                certificate2.checkValidity();
                assertTrue(toHex(certificate2.getSigAlgParams()).equals(hexSHA256Salt40));
                java.security.cert.CertificateFactory cf2 = java.security.cert.CertificateFactory
                        .getInstance("X.509", "BC");
                InputStream istream2 = new ByteArrayInputStream(derBytes2);
                java.security.cert.Certificate cert2 = cf2.generateCertificate(istream2);
                assertTrue(cert2 != null);

                try {
                    cert2.verify(cert2.getPublicKey());
                    //assertTrue(false);
                } catch (Exception e) {

                    assertTrue(e.getMessage()
                            .contains("certificate does not verify with supplied key"));
                }


                break;

            case PARAMS_SALT40:
                PSSParameterSpec pssParameterSpec3 = new PSSParameterSpec("SHA-1", "MGF1",
                        MGF1ParameterSpec.SHA1, 40, 1);
                keypair.generate(keysize);
                X509Certificate[] chain3 = new X509Certificate[1];

                chain3[0] = keypair.getSelfCert(x500Name, (long) validity * 24 * 60 * 60,
                        (AlgorithmParameterSpec) pssParameterSpec3);

                byte[] derBytes3 = chain3[0].getEncoded();
                if (printJunitTrace)
                    System.out.println("signed certificate3=" + toHex(derBytes3));

                InputStream is3 = new ByteArrayInputStream(derBytes3);
                X509Certificate certificate3 = (X509Certificate) CertificateFactory
                        .getInstance("X.509").generateCertificate(is3);
                if (printJunitTrace)
                    System.out.println(
                            "Certificate3 parameters=" + toHex(certificate3.getSigAlgParams()));
                certificate3.checkValidity();
                //X509CertImpl certImpl3 = (X509CertImpl) certificate3;
                certificate3.verify(certificate3.getPublicKey(), (String) null);
                //assertTrue(toHex(certificate3.getSigAlgParams())
                //        .equals("302ca00b300906052b0e03021a0500a118301606092a864886f70d010108300906052b0e03021a0500a203020128"));

                java.security.cert.CertificateFactory cf3 = java.security.cert.CertificateFactory
                        .getInstance("X.509", "BC");
                InputStream istream3 = new ByteArrayInputStream(derBytes3);
                java.security.cert.Certificate cert3 = cf3.generateCertificate(istream3);
                assertTrue(cert3 != null);
                cert3.verify(cert3.getPublicKey());
                assertTrue(Arrays.equals(cert3.getEncoded(), certificate3.getEncoded()));

                break;

            default:
                assertTrue(false);
        }

    }



    public void testReadDefaultParams3rdPartyCertificates()
            throws IOException, CertificateException, InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException, InvalidParameterSpecException,
            InvalidAlgorithmParameterException {
        CertificateFactory.getInstance("X.509");

        if (printJunitTrace)
            System.out.println(new File(".").getAbsolutePath());


        String defaultParamsClientFileName = "src/test/java/ibm/jceplus/certs3rdparty/defaultParams/pssClientCert.pem";
        String defaultParamsRootFileName = "src/test/java/ibm/jceplus/certs3rdparty/defaultParams/pssRootCert.pem";

        BufferedInputStream bisDefaultParamsRoot = null;
        File fileDefaultParamsRoot = new File(defaultParamsRootFileName);
        try {
            bisDefaultParamsRoot = new BufferedInputStream(
                    new FileInputStream(fileDefaultParamsRoot));
        } catch (FileNotFoundException e) {
            throw new IOException("Could not locate keyfile at '" + defaultParamsRootFileName + "'",
                    e);
        }
        byte[] defaultParamsRootBytes = new byte[(int) fileDefaultParamsRoot.length()];
        bisDefaultParamsRoot.read(defaultParamsRootBytes);
        bisDefaultParamsRoot.close();

        InputStream isDefaultParamsRoot = new ByteArrayInputStream(defaultParamsRootBytes);
        X509Certificate certDefaultParamsRoot = (X509Certificate) CertificateFactory
                .getInstance("X.509").generateCertificate(isDefaultParamsRoot);
        certDefaultParamsRoot.checkValidity();
        certDefaultParamsRoot.verify(certDefaultParamsRoot.getPublicKey());

        BufferedInputStream bisDefaultParamsClient = null;
        File fileDefaultParamsClient = new File(defaultParamsClientFileName);
        try {
            bisDefaultParamsClient = new BufferedInputStream(
                    new FileInputStream(fileDefaultParamsClient));
        } catch (FileNotFoundException e) {
            throw new IOException(
                    "Could not locate keyfile at '" + defaultParamsClientFileName + "'", e);
        }
        byte[] defaultParamsClientBytes = new byte[(int) fileDefaultParamsClient.length()];
        bisDefaultParamsClient.read(defaultParamsClientBytes);
        bisDefaultParamsClient.close();

        InputStream isDefaultParamsClient = new ByteArrayInputStream(defaultParamsClientBytes);
        X509Certificate certDefaultParamsClient = (X509Certificate) CertificateFactory
                .getInstance("X.509").generateCertificate(isDefaultParamsClient);
        certDefaultParamsClient.checkValidity();

        certDefaultParamsClient.verify(certDefaultParamsRoot.getPublicKey(), (String) null);

        //        X509CertImpl certImplDefaultParamsClient = (X509CertImpl) certDefaultParamsClient;
        //
        //        certImplDefaultParamsClient.verify(
        //                certDefaultParamsRoot.getPublicKey(), null,
        //                certDefaultParamsClient.getSigAlgParams());
    }

    @Test
    public void testReadEmptyParam3rdPartyCertificates() throws IOException, CertificateException,
            InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
            SignatureException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
        CertificateFactory.getInstance("X.509");

        String emptyParamsClientFileName = "src/test/java/ibm/jceplus/certs3rdparty/emptyParams/pssClientCert.pem";
        String emptyParamsRootFileName = "src/test/java/ibm/jceplus/certs3rdparty/emptyParams/pssRootCert.pem";

        BufferedInputStream bisEmptyParamsRoot = null;
        File fileEmptyParamsRoot = new File(emptyParamsRootFileName);
        try {
            bisEmptyParamsRoot = new BufferedInputStream(new FileInputStream(fileEmptyParamsRoot));
        } catch (FileNotFoundException e) {
            throw new IOException("Could not locate keyfile at '" + emptyParamsRootFileName + "'",
                    e);
        }
        byte[] emptyParamsRootBytes = new byte[(int) fileEmptyParamsRoot.length()];
        bisEmptyParamsRoot.read(emptyParamsRootBytes);
        bisEmptyParamsRoot.close();

        InputStream isEmptyParamsRoot = new ByteArrayInputStream(emptyParamsRootBytes);
        X509Certificate certEmptyParamsRoot = (X509Certificate) CertificateFactory
                .getInstance("X.509").generateCertificate(isEmptyParamsRoot);
        certEmptyParamsRoot.checkValidity();

        certEmptyParamsRoot.verify(certEmptyParamsRoot.getPublicKey());


        BufferedInputStream bisEmptyParamsClient = null;
        File fileEmptyParamsClient = new File(emptyParamsClientFileName);
        try {
            bisEmptyParamsClient = new BufferedInputStream(
                    new FileInputStream(fileEmptyParamsClient));
        } catch (FileNotFoundException e) {
            throw new IOException("Could not locate keyfile at '" + emptyParamsClientFileName + "'",
                    e);
        }
        byte[] emptyParamsClientBytes = new byte[(int) fileEmptyParamsClient.length()];
        bisEmptyParamsClient.read(emptyParamsClientBytes);
        bisEmptyParamsClient.close();

        InputStream isEmptyParamsClient = new ByteArrayInputStream(emptyParamsClientBytes);
        X509Certificate certEmptyParamsClient = (X509Certificate) CertificateFactory
                .getInstance("X.509").generateCertificate(isEmptyParamsClient);
        certEmptyParamsClient.checkValidity();

        certEmptyParamsClient.verify(certEmptyParamsRoot.getPublicKey(), (String) null);

        //        X509CertImpl certImplEmptyParamsClient = (X509CertImpl) certEmptyParamsClient;
        //        if (certEmptyParamsClient.getSigAlgParams() != null) {
        //            certImplEmptyParamsClient.verify(
        //                    certEmptyParamsRoot.getPublicKey(), null,
        //                    certEmptyParamsClient.getSigAlgParams());
        //        } else {
        //            certImplEmptyParamsRoot.verify(certEmptyParamsRoot.getPublicKey());
        //        }

    }

    /**
     * Test parameter spec
     * @throws IOException
     */
    @Test
    public void testParameterSpec() throws IOException {
        Signature sig_ibm = null;
        try {
            sig_ibm = Signature.getInstance(IBM_ALG, getProviderName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            assertTrue(false);
        }

        AlgorithmParameters algParams_ibm = sig_ibm.getParameters();
        if (printJunitTrace)
            System.out.println("algParams_ibm=" + algParams_ibm.toString());

        assertTrue(algParams_ibm.toString().contains("hashAlgorithm: SHA"));
        assertTrue(algParams_ibm.toString().contains("maskGenAlgorithm: MGF1"));
        assertTrue(algParams_ibm.toString().contains("mgf1ParameterSpec: SHA-1"));
        assertTrue(algParams_ibm.toString().contains("saltLength: 20"));
        assertTrue(algParams_ibm.toString().contains("trailerField: 1"));


        PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA2", "MGF1",
                MGF1ParameterSpec.SHA256, 400, 1);
        try {
            sig_ibm.setParameter(pssParameterSpec);
        } catch (InvalidAlgorithmParameterException e1) {
            e1.printStackTrace();
            assertTrue(false);
        }

        AlgorithmParameters algParams_ibm1 = sig_ibm.getParameters();
        if (printJunitTrace)
            System.out.println("algParams_ibm1=" + algParams_ibm1);
        assertTrue(algParams_ibm1.toString().contains("hashAlgorithm: SHA-256")
                || algParams_ibm1.toString().contains("hashAlgorithm: SHA2"));
        assertTrue(algParams_ibm1.toString().contains("saltLength: 400"));

        Signature sig_bc = null;
        try {
            sig_bc = Signature.getInstance(BC_ALG, "BC");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            assertTrue(false);
        }

        AlgorithmParameters algParams_bc = sig_bc.getParameters();
        if (printJunitTrace)
            System.out.println("algParams_bc=" + algParams_bc.toString());

        ASN1InputStream aIn = new ASN1InputStream(algParams_bc.getEncoded("ASN.1"));
        ASN1Dump.dumpAsString(aIn.readObject()).equals("DER Sequence");

        PSSParameterSpec pssParameterSpec_bc = new PSSParameterSpec("SHA1", "MGF1",
                MGF1ParameterSpec.SHA1, 400, 1);

        // PSSParameterSpec pssParameterSpec = new PSSParameterSpec(100);
        try {
            sig_bc.setParameter(pssParameterSpec_bc);
        } catch (InvalidAlgorithmParameterException e1) {
            e1.printStackTrace();
            assertTrue(false);
        }
        AlgorithmParameters algParams_bc1 = sig_bc.getParameters();
        ASN1InputStream aIn_bc1 = new ASN1InputStream(algParams_bc1.getEncoded("ASN.1"));
        ASN1Dump.dumpAsString(aIn_bc1.readObject())
                .equals("Sequence\n\t\tTagged [2]\n\t\tInteger(400)");
        //Sequence
        //Tagged [2]
        //    Integer(400)

        if (printJunitTrace)
            System.out.println("algParams_bc1=" + algParams_bc1.toString());

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

    @Test
    public void testRSAPSSKeyFactory() throws Exception {
        try {
            String providerNameKF = "";
            providerNameKF = getProviderName();
            if (printJunitTrace)
                System.out.println("Test RSAPSS KeyFactory provider: " + providerNameKF);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", providerNameKF);
            keyGen.initialize(1024, new java.security.SecureRandom());
            KeyPair keyPair = keyGen.genKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

            KeyFactory kf = KeyFactory.getInstance("RSASSA-PSS", providerNameKF);
            X509EncodedKeySpec x509KeySpec = kf.getKeySpec(publicKey,
                    X509EncodedKeySpec.class);
            byte[] encodedKey = x509KeySpec.getEncoded();

            X509EncodedKeySpec x509KeySpec2 = new X509EncodedKeySpec(encodedKey);
            KeyFactory.getInstance("RSASSA-PSS", providerNameKF);
            RSAPublicKey publicKey2 = (RSAPublicKey) kf.generatePublic(x509KeySpec2);
            assertTrue("Algorithm name different",
                    publicKey.getAlgorithm().equalsIgnoreCase(publicKey2.getAlgorithm()));
            assertTrue("Modulus different", publicKey.getModulus().equals(publicKey2.getModulus()));
            assertTrue("Exponentdifferent",
                    publicKey.getPublicExponent().equals(publicKey2.getPublicExponent()));

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }
}
