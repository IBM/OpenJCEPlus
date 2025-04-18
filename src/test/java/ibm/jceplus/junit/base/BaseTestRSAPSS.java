/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

// A test program to test all DSA classes
package ibm.jceplus.junit.base;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestRSAPSS extends BaseTestJunit5 {

    String IBM_ALG = "RSASA-PSS";
    //String BC_ALG = "SHA1withRSAandMGF1";
    String BC_ALG = "RSASA-PSS";
    static final String msg = "This is hello Karthik";

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

    private final static BigInteger N = new BigInteger(
            "116231208661367609700141079576488663663527180869991078124978203037949869"
                    + "312762870627991319537001781149083155962615105864954367253799351549459177"
                    + "839995715202060014346744789001273681801687605044315560723525700773069112"
                    + "214443196787519930666193675297582113726306864236010438506452172563580739"
                    + "994193451997175316921");

    private final static BigInteger E = BigInteger.valueOf(65537);

    private final static BigInteger D = new BigInteger(
            "528278531576995741358027120152717979850387435582102361125581844437708890"
                    + "736418759997555187916546691958396015481089485084669078137376029510618510"
                    + "203389286674134146181629472813419906337170366867244770096128371742241254"
                    + "843638089774095747779777512895029847721754360216404183209801002443859648"
                    + "26168432372077852785");

    // Used by doGenKeyPair method
    final int EMPTY_PARAMS = 0;
    final int DEFAULT_PARAMS = 1;
    final int NONDEFAULT_PARAMS = 2;
    final int PARAMS_SALT40 = 3;

    static boolean printJunitTrace = false;

    @Test
    public void testRSAPlainKeySignatureWithPSS() throws Exception {
        KeyFactory kf;

        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support RSA plain keys
            return;
        }

        kf = KeyFactory.getInstance("RSA", getProviderName());

        RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(N, E);
        PublicKey publicKey = kf.generatePublic(pubSpec);

        RSAPrivateKeySpec privSpec = new RSAPrivateKeySpec(N, D);
        PrivateKey privateKey = kf.generatePrivate(privSpec);

        PSSParameterSpec pssParameter = new PSSParameterSpec("SHA1", "MGF1", MGF1ParameterSpec.SHA1,
                20, 1);

        // Generate Signature
        Signature sig = Signature.getInstance("RSAPSS", getProviderName());
        if (pssParameter != null) {
            sig.setParameter(pssParameter);
            AlgorithmParameters algParams = sig.getParameters();
            algParams.getParameterSpec(PSSParameterSpec.class);
        }

        AlgorithmParameters algParams = sig.getParameters();
        algParams.getParameterSpec(PSSParameterSpec.class);
        sig.initSign(privateKey);
        sig.update(content);
        byte[] sigBytes = sig.sign();

        // Check Signature
        sig.initVerify(publicKey);
        sig.update(content);

        boolean signatureVerified = sig.verify(sigBytes);

        assertTrue(signatureVerified, "signature is invalid!!");
    }

    @Test
    public void testRSASignatureWithPSS_SHA1() throws Exception {
        try {
            //dotestSignature(content, IBM_ALG, 1024, null, providerName);
            int keySize = 1024;

            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                keySize = 2048;
            }
            dotestSignature(msg.getBytes(), IBM_ALG, keySize, null, getProviderName());

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Change the keysize in steps of 32 or 512 to speed up the test case
     * Generate a key once and use it for multiple tests - The OpenJCEPlusFIPS does not allow keysize < 2048
     * @throws Exception
     */
    @Test
    public void testRSASignatureWithPSSBigMsgMultiKeySize() throws Exception {
        try {
            int startSize = 1024;

            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                startSize = 2048;
            }
            for (int i = startSize; i < 4096;) {
                if (printJunitTrace)
                    System.out.println("keySize=" + i);
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", getProviderName());
                keyGen.initialize(i, new java.security.SecureRandom());
                KeyPair keyPair = keyGen.genKeyPair();
                dotestSignature(content3, IBM_ALG, keyPair, null);
                dotestSignature(oneByte, IBM_ALG, keyPair, null);
                dotestSignature(content, IBM_ALG, keyPair, null);
                i = i + 512;
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
    public void testRSASignatureWithPSSMultiByteSize_timed() throws Exception {
        try {
            int keySize = 1024;

            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                keySize = 2048;
            }

            for (int i = 1; i <= 100; i++) {
                byte[] dynMsg = new byte[i * 11];
                for (int j = 0; j < i; j++) {
                    System.arraycopy(elevenBytes, 0, dynMsg, j * 11, 11);
                }
                if (printJunitTrace)
                    System.out.println("msgSize=" + dynMsg.length);
                //dotestSignature(dynMsg, IBM_ALG, 512, null, providerName);

                dotestSignature(dynMsg, IBM_ALG, keySize, null, getProviderName());
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
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
                return;
            }

            dotestSignaturePSSParameterSpec(content1, IBM_ALG, 1024);

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
     * PSSParameterSpec with different message digest and MGF1
     * According to [PKCS#1v2.1] the mask generation function (MGF) 
     * – if based on a hash algo is recommended to use the same hash 
     * function as the hash function fingerprinting the message. 
     * 
     * However the structures in [PKCS#1v2.1] allow for separate 
     * parameterization of the MGF and the message digest.
     * 
     * OpenJCEPlus uses the same message digest, this test aims to
     * check if RSAPSSSignature will fail if different MD is used.
     * @throws Exception
     */
    @ParameterizedTest
    @CsvSource({"SHA256, SHA384",
                "SHA256, SHA512",
                "SHA384, SHA512",
                "SHA512, SHA384"})
    public void testRSASignatureDifferentMGFandMD(String mdName, String mgfSpecMD) throws Exception {
        AlgorithmParameterSpec mgfSpec = null;

        switch (mgfSpecMD) {
            case "SHA256":
                mgfSpec = MGF1ParameterSpec.SHA256;
                break;
            case "SHA384":
                mgfSpec = MGF1ParameterSpec.SHA384;
                break;
            case "SHA512":
                mgfSpec = MGF1ParameterSpec.SHA512;
                break;
            default:
                mgfSpec = MGF1ParameterSpec.SHA512;
                break;
        }
        PSSParameterSpec pssParameter = new PSSParameterSpec(mdName, "MGF1",
                mgfSpec, 20, 1);
        try {
            dotestSignature(content, IBM_ALG, 2048, pssParameter, getProviderName());
            fail("Expected exception not thrown");
        } catch (InvalidAlgorithmParameterException iape) {
            assertEquals("The message digest within the PSSParameterSpec does not match the MGF message digest.", iape.getMessage());
        }
    }

    /**
     * SHA256 - test one byte
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
     * Helper method
     * @param content
     * @param algorithm
     * @param keySize
     * @param pssParameterSpec
     * @param jceprovider
     * @throws Exception
     */

    protected void dotestSignature(byte[] content, String algorithm, int keySize,
            PSSParameterSpec pssParameterSpec, String providerName) throws Exception {

        // Generate Signature

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", providerName);
        keyGen.initialize(keySize, new java.security.SecureRandom());
        KeyPair keyPair = keyGen.genKeyPair();

        Signature sig = Signature.getInstance(algorithm, providerName);
        if (pssParameterSpec != null) {
            sig.setParameter(pssParameterSpec);
            //To-Do AlgorithmParameters algParams = sig.getParameters();
            //To-Do algParams.getParameterSpec(PSSParameterSpec.class);
        }

        //AlgorithmParameters algParams = sig.getParameters();
        //algParams.getParameterSpec(PSSParameterSpec.class);
        sig.initSign(keyPair.getPrivate());
        sig.update(content);
        byte[] sigBytes = sig.sign();

        // Verify the signature
        sig.initVerify(keyPair.getPublic());
        sig.update(content);

        // Check Signature
        // Signature verifySig = Signature.getInstance("SHA1withRSA/PSS",
        // JCE_PROVIDER);
        // verifySig.initVerify(cert);
        // verifySig.update(content);
        boolean signatureVerified = sig.verify(sigBytes);

        assertTrue(signatureVerified, "signature is invalid!!");
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

        // KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", providerName);
        // keyGen.initialize(keySize, new java.security.SecureRandom());
        // KeyPair keyPair = keyGen.genKeyPair();

        Signature sig = Signature.getInstance(algorithm, getProviderName());
        if (pssParameterSpec != null) {
            if (printJunitTrace)
                System.out.println("calling sig.setParameter");
            sig.setParameter(pssParameterSpec);
        }
        sig.initSign(keyPair.getPrivate());
        sig.update(content);
        byte[] sigBytes = sig.sign();

        // Verify the signature
        sig.initVerify(keyPair.getPublic());
        sig.update(content);

        // Check Signature
        // Signature verifySig = Signature.getInstance("SHA1withRSA/PSS", providerName);
        // verifySig.initVerify(cert);
        // verifySig.update(content);
        boolean signatureVerified = sig.verify(sigBytes);

        assertTrue(signatureVerified, "signature is invalid!!");
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

        if (getProviderName().equals("OpenJCEPlusFIPS") && keySize == 1024) {
            assertTrue(true);
            return;
        }

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", getProviderName());
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

        assertTrue(signatureVerified, "signature is invalid!!");
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

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", getProviderName());
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

        assertTrue(signatureVerified, "signature is invalid!!");
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
            int keySize = 1024;

            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                keySize = 2048;
            }

            if (printJunitTrace)
                System.out.println("Test RSAPSS KeyFactory provider: " + getProviderName());
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", getProviderName());
            keyGen.initialize(keySize, new java.security.SecureRandom());
            KeyPair keyPair = keyGen.genKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

            KeyFactory kf = KeyFactory.getInstance("RSASSA-PSS", getProviderName());
            X509EncodedKeySpec x509KeySpec = kf.getKeySpec(publicKey,
                    X509EncodedKeySpec.class);
            byte[] encodedKey = x509KeySpec.getEncoded();

            X509EncodedKeySpec x509KeySpec2 = new X509EncodedKeySpec(encodedKey);
            KeyFactory.getInstance("RSASSA-PSS", getProviderName());
            RSAPublicKey publicKey2 = (RSAPublicKey) kf.generatePublic(x509KeySpec2);
            assertTrue(publicKey.getAlgorithm().equalsIgnoreCase(publicKey2.getAlgorithm()), "Algorithm name different");
            assertTrue(publicKey.getModulus().equals(publicKey2.getModulus()), "Modulus different");
            assertTrue(publicKey.getPublicExponent().equals(publicKey2.getPublicExponent()), "Exponent different");

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }
}
