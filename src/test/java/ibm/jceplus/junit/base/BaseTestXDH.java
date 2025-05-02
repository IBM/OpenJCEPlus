/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.List;
import javax.crypto.KeyAgreement;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestXDH extends BaseTestJunit5 {

    @Test
    public void testXDH_X25519() throws Exception {
        String curveName = "X25519";
        NamedParameterSpec nps = new NamedParameterSpec(curveName);
        compute_xdh_key(curveName, nps);
    }

    @Test
    public void testXDH_X448() throws Exception {
        String curveName = "X448";
        NamedParameterSpec nps = new NamedParameterSpec(curveName);
        compute_xdh_key(curveName, nps);
    }

    @Test
    public void testXDH_runBasicTests() throws Exception {

        System.out.println(
                "\n\n\n\n************************** Starting runBasic ************************");
        runBasicTests();
    }

    @Test
    public void testXDH_runKAT() throws Exception {

        System.out.println(
                "\n\n\n\n************************** Starting runKAT ************************");
        runKAT();
    }

    @Test
    public void testXDH_runSmallOrderTest() throws Exception {

        System.out.println(
                "\n\n\n\n************************** Starting runSmallOrderTest ************************");
        runSmallOrderTest();
    }

    @Test
    public void testXDH_runNonCanonicalTest() throws Exception {

        System.out.println(
                "\n\n\n\n************************** Starting runNonCanonicalTest ************************");
        runNonCanonicalTest();
    }

    @Test
    public void testXDH_runCurveMixTest() throws Exception {

        System.out.println(
                "\n\n\n\n************************** Starting runCurveMixTest ************************");
        runCurveMixTest();
    }

    @Test
    public void test_engineGenerateSecret() throws Exception {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("DH", getProviderName());
            KeyPair kp1 = g.generateKeyPair();
            KeyPair kp2 = g.generateKeyPair();
            KeyAgreement ka = KeyAgreement.getInstance("DH", getProviderName());
            for (String alg : List.of("TlsPremasterSecret", "Generic")) {
                ka.init(kp1.getPrivate());
                ka.doPhase(kp2.getPublic(), true);
                assertEquals(ka.generateSecret(alg).getAlgorithm(), alg);
            }
        } catch (Exception e) {
            throw e;
        }
    }

    void compute_xdh_key(String idString, NamedParameterSpec algParameterSpec)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchProviderException, InvalidKeyException {
        //final String methodName = "compute_xdh_key" + "_" + idString;

        KeyPairGenerator kpgA = null;
        try {
            kpgA = KeyPairGenerator.getInstance("XDH", getProviderName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }

        try {
            kpgA.initialize(algParameterSpec);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw e;
        }

        KeyPair keyPairA = kpgA.generateKeyPair();

        // set up
        KeyAgreement keyAgreeA = null;
        try {
            keyAgreeA = KeyAgreement.getInstance("XDH", getProviderName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }
        // Two party agreement
        try {
            keyAgreeA.init(keyPairA.getPrivate());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw e;
        }
        KeyPairGenerator kpgB = null;

        try {
            kpgB = KeyPairGenerator.getInstance("XDH", getProviderName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }

        try

        {
            kpgB.initialize(algParameterSpec);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw e;
        }

        KeyPair keyPairB = kpgB.generateKeyPair();
        //        System.out.println("KeyPairB.privKey=" + BaseUtils.bytesToHex(keyPairB.getPrivate().getEncoded()));
        //        System.out.println("KeyPairB.publicKey=" + BaseUtils.bytesToHex(keyPairB.getPublic().getEncoded()));

        KeyAgreement keyAgreeB = null;
        try {
            keyAgreeB = KeyAgreement.getInstance("XDH", getProviderName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }

        try {
            keyAgreeB.init(keyPairB.getPrivate());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw e;
        }

        try {
            keyAgreeA.doPhase(keyPairB.getPublic(), true);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalStateException e) {
            e.printStackTrace();
            throw e;
        }
        try {
            keyAgreeB.doPhase(keyPairA.getPublic(), true);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw e;
        } catch (IllegalStateException e) {
            e.printStackTrace();
            throw e;
        }

        // Generate the key bytes
        byte[] sharedSecretA = keyAgreeA.generateSecret();
        byte[] sharedSecretB = keyAgreeB.generateSecret();

        assertTrue(Arrays.equals(sharedSecretA, sharedSecretB));

    }

    private void runBasicTests() throws Exception {
        runBasicTest("XDH", null);
        runBasicTest("XDH", 255);
        runBasicTest("XDH", 448);
        runBasicTest("XDH", "X25519");
        runBasicTest("XDH", "X448");
        runBasicTest("X25519", null);
        runBasicTest("X448", null);
        runBasicTest("1.3.101.110", null);
        runBasicTest("1.3.101.111", null);
        runBasicTest("OID.1.3.101.110", null);
        runBasicTest("OID.1.3.101.111", null);
    }

    private void runBasicTest(String name, Object param) throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(name, getProviderName());
        AlgorithmParameterSpec paramSpec = null;

        System.out.println("Name: " + name);
        if (param instanceof Integer) {
            kpg.initialize((Integer) param);
        } else if (param instanceof String) {
            //System.out.println("Params: " + param);
            paramSpec = new NamedParameterSpec((String) param);
            kpg.initialize(paramSpec);
        }
        KeyPair kp = kpg.generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance(name, getProviderName());
        ka.init(kp.getPrivate(), paramSpec);
        ka.doPhase(kp.getPublic(), true);

        byte[] secret = ka.generateSecret();

        KeyFactory kf = KeyFactory.getInstance(name, getProviderName());
        // Test with X509 and PKCS8 key specs
        X509EncodedKeySpec pubSpec = kf.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);
        //System.out.println("After getKeySpec");
        PKCS8EncodedKeySpec priSpec = kf.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);

        PublicKey pubKey = kf.generatePublic(pubSpec);
        //System.out.println("After generatePublic");
        PrivateKey priKey = kf.generatePrivate(priSpec);

        ka.init(priKey);
        ka.doPhase(pubKey, true);
        byte[] secret2 = ka.generateSecret();
        if (!Arrays.equals(secret, secret2)) {
            throw new RuntimeException("Arrays not equal");
        }

        // make sure generateSecret() resets the state to after init()
        try {
            ka.generateSecret();
            throw new RuntimeException("generateSecret does not reset state");
        } catch (IllegalStateException ex) {
            // do nothing---this is expected
        }
        ka.doPhase(pubKey, true);
        ka.generateSecret();

        // test with XDH key specs
        XECPublicKeySpec xdhPublic = kf.getKeySpec(kp.getPublic(), XECPublicKeySpec.class);
        //System.out.println("After getKeySpec 2");
        XECPrivateKeySpec xdhPrivate = kf.getKeySpec(kp.getPrivate(), XECPrivateKeySpec.class);
        PublicKey pubKey2 = kf.generatePublic(xdhPublic); // Died
        //System.out.println("After generatePublic 2");
        PrivateKey priKey2 = kf.generatePrivate(xdhPrivate);
        ka.init(priKey2);
        ka.doPhase(pubKey2, true);
        byte[] secret3 = ka.generateSecret();

        if (!Arrays.equals(secret, secret3)) {
            throw new RuntimeException("Arrays not equal");
        }

        assertTrue(true);
    }

    private void runSmallOrderTest() throws Exception {
        // Ensure that small-order points are rejected

        // X25519
        // 0
        testSmallOrder("X25519", "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000");
        // 1 and -1
        testSmallOrder("X25519", "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A",
                "0100000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000");

        //Public keys created okay and shouldn't be.
        testSmallOrder("X25519", "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A",
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "0000000000000000000000000000000000000000000000000000000000000000");

        // order 8 points
        testSmallOrder("X25519", "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A",
                "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
                "0000000000000000000000000000000000000000000000000000000000000000");
        testSmallOrder("X25519", "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A",
                "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
                "0000000000000000000000000000000000000000000000000000000000000000");

        // X448
        // 0
        testSmallOrder("X448",
                "9A8F4925D1519F5775CF46B04B5800D4EE9EE8BAE8BC5565D498C28DD9C9BA"
                        + "F574A9419744897391006382A6F127AB1D9AC2D8C0A598726B",
                "00000000000000000000000000000000000000000000000000000000000000"
                        + "00000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000"
                        + "00000000000000000000000000000000000000000000000000");
        // 1 and -1
        testSmallOrder("X448",
                "9A8F4925D1519F5775CF46B04B5800D4EE9EE8BAE8BC5565D498C28DD9C9BA"
                        + "F574A9419744897391006382A6F127AB1D9AC2D8C0A598726B",
                "01000000000000000000000000000000000000000000000000000000000000"
                        + "00000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000"
                        + "00000000000000000000000000000000000000000000000000");
        testSmallOrder("X448",
                "9A8F4925D1519F5775CF46B04B5800D4EE9EE8BAE8BC5565D498C28DD9C9BAF"
                        + "574A9419744897391006382A6F127AB1D9AC2D8C0A598726B",
                "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff"
                        + "fffffffffffffffffffffffffffffffffffffffffffffffff",
                "000000000000000000000000000000000000000000000000000000000000000"
                        + "0000000000000000000000000000000000000000000000000");
    }

    private void testSmallOrder(String name, String a_pri, String b_pub, String result)
            throws Exception {

        try {
            runDiffieHellmanTest(name, a_pri, b_pub, result);
            throw new RuntimeException("Expected exception not thrown on small-order point test.");
        } catch (InvalidKeyException ex) {
            assertEquals("Point has small order.", ex.getMessage());
        }
    }

    private void runNonCanonicalTest() throws Exception {
        // Test non-canonical values

        // high bit of public key set
        // X25519
        runDiffieHellmanTest("X25519",
                "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A",
                "DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B8F",
                "954e472439316f118ae158b65619eecff9e6bcf51ab29add66f3fd088681e233");

        runDiffieHellmanTest(
                "302e020100300706032b656e0500042077076d0a7318a57d3c16c17251b266"
                        + "45df4c2f87ebc0992ab177fba51db92c2a",
                "302c300706032b656e0500032100de9edb7d7b7dc1b4d35b61c2ece435373f"
                        + "8343c85b78674dadfc7e146f882b8f",
                "954e472439316f118ae158b65619eecff9e6bcf51ab29add66f3fd088681e233");

        // large public key

        // X25519
        // public key value is 2^255-2
        runDiffieHellmanTest("X25519",
                "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A",
                "FEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
                "81a02a45014594332261085128959869fc0540c6b12380f51db4b41380de2c2c");

        runDiffieHellmanTest(
                "302e020100300706032b656e0500042077076d0a7318a57d3c16c17251b266"
                        + "45df4c2f87ebc0992ab177fba51db92c2a",
                "302c300706032b656e0500032100FEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        + "FFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
                "81a02a45014594332261085128959869fc0540c6b12380f51db4b41380de2c2c");

        // X448
        // public key value is 2^448-2 - will not create Public Key????
        runDiffieHellmanTest("X448",
                "9A8F4925D1519F5775CF46B04B5800D4EE9EE8BAE8BC5565D498C28DD9C9BA"
                        + "F574A9419744897391006382A6F127AB1D9AC2D8C0A598726B",
                "FEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        + "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "66e2e682b1f8e68c809f1bb3e406bd826921d9c1a5bfbfcbab7ae72feecee6"
                        + "3660eabd54934f3382061d17607f581a90bdac917a064959fb");

        runDiffieHellmanTest(
                "3046020100300706032B656F050004389A8F4925D1519F5775CF46B04B5800"
                        + "D4EE9EE8BAE8BC5565D498C28DD9C9BAF574A9419744897391006382A6F127"
                        + "AB1D9AC2D8C0A598726B",
                "3044300706032B656F0500033900FEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        + "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        + "FFFFFFFFFFFFFFFF",
                "66e2e682b1f8e68c809f1bb3e406bd826921d9c1a5bfbfcbab7ae72feecee6"
                        + "3660eabd54934f3382061d17607f581a90bdac917a064959fb");

    }

    private void runKAT() throws Exception {
        // Test both sides of the key exchange using vectors in RFC 7748

        // X25519
        // raw
        runDiffieHellmanTest("X25519",
                "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A",
                "DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F",
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        runDiffieHellmanTest("X25519",
                "5DAB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E0EB",
                "8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A",
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        // encoded
        runDiffieHellmanTest(
                "302E020100300706032B656E0500042077076D0A7318A57D3C16C17251B266"
                        + "45DF4C2F87EBC0992AB177FBA51DB92C2A",
                "302C300706032B656E0500032100DE9EDB7D7B7DC1B4D35B61C2ECE435373F"
                        + "8343C85B78674DADFC7E146F882B4F",
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        runDiffieHellmanTest(
                "302E020100300706032B656E050004205DAB087E624A8A4B79E17F8B83800E"
                        + "E66F3BB1292618B6FD1C2F8B27FF88E0EB",
                "302C300706032B656E05000321008520F0098930A754748B7DDCB43EF75A0D"
                        + "BF3A0D26381AF4EBA4A98EAA9B4E6A",
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        // X448
        //raw
        runDiffieHellmanTest("X448",
                "9A8F4925D1519F5775CF46B04B5800D4EE9EE8BAE8BC5565D498C28DD9C9BA"
                        + "F574A9419744897391006382A6F127AB1D9AC2D8C0A598726B",
                "3EB7A829B0CD20F5BCFC0B599B6FECCF6DA4627107BDB0D4F345B43027D8B9"
                        + "72FC3E34FB4232A13CA706DCB57AEC3DAE07BDC1C67BF33609",
                "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b"
                        + "56fd2464c335543936521c24403085d59a449a5037514a879d");

        runDiffieHellmanTest("X448",
                "1C306A7AC2A0E2E0990B294470CBA339E6453772B075811D8FAD0D1D6927C1"
                        + "20BB5EE8972B0D3E21374C9C921B09D1B0366F10B65173992D",
                "9B08F7CC31B7E3E67D22D5AEA121074A273BD2B83DE09C63FAA73D2C22C5D9"
                        + "BBC836647241D953D40C5B12DA88120D53177F80E532C41FA0",
                "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b"
                        + "56fd2464c335543936521c24403085d59a449a5037514a879d");

        //encoded
        runDiffieHellmanTest(
                "3046020100300706032B656F050004389A8F4925D1519F5775CF46B04B5800"
                        + "D4EE9EE8BAE8BC5565D498C28DD9C9BAF574A9419744897391006382A6F127"
                        + "AB1D9AC2D8C0A598726B",
                "3044300706032B656F05000339003EB7A829B0CD20F5BCFC0B599B6FECCF6D"
                        + "A4627107BDB0D4F345B43027D8B972FC3E34FB4232A13CA706DCB57AEC3DAE"
                        + "07BDC1C67BF33609",
                "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b"
                        + "56fd2464c335543936521c24403085d59a449a5037514a879d");

        runDiffieHellmanTest(
                "3046020100300706032B656F050004381C306A7AC2A0E2E0990B294470CBA3"
                        + "39E6453772B075811D8FAD0D1D6927C120BB5EE8972B0D3E21374C9C921B09"
                        + "D1B0366F10B65173992D",
                "3044300706032B656F05000339009B08F7CC31B7E3E67D22D5AEA121074A27"
                        + "3BD2B83DE09C63FAA73D2C22C5D9BBC836647241D953D40C5B12DA88120D53"
                        + "177F80E532C41FA0",
                "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b"
                        + "56fd2464c335543936521c24403085d59a449a5037514a879d");
    }

    private void runDiffieHellmanTest(String a_pri, String b_pub, String result) throws Exception {

        KeyFactory kf = KeyFactory.getInstance("XDH", getProviderName());
        byte[] a_pri_ba = BaseUtils.hexStringToByteArray(a_pri);
        KeySpec privateSpec = new PKCS8EncodedKeySpec(a_pri_ba);
        PrivateKey privateKey = kf.generatePrivate(privateSpec);
        byte[] b_pub_ba = BaseUtils.hexStringToByteArray(b_pub);
        KeySpec publicSpec = new X509EncodedKeySpec(b_pub_ba);
        PublicKey publicKey = kf.generatePublic(publicSpec);

        KeyAgreement ka = KeyAgreement.getInstance("XDH", getProviderName());
        ka.init(privateKey);
        ka.doPhase(publicKey, true);

        byte[] sharedSecret = ka.generateSecret();
        byte[] expectedResult = BaseUtils.hexStringToByteArray(result);
        if (!Arrays.equals(sharedSecret, expectedResult)) {
            throw new RuntimeException(
                    "fail: expected=" + result + ", actual=" + byteArrayToHexString(sharedSecret));
        }

        assertTrue(true);

    }

    private void runDiffieHellmanTest(String curveName, String a_pri, String b_pub, String result)
            throws Exception {

        System.out.println("Test curve = " + curveName);
        NamedParameterSpec paramSpec = new NamedParameterSpec(curveName);
        KeyFactory kf = KeyFactory.getInstance("XDH", getProviderName());
        KeySpec privateSpec = new XECPrivateKeySpec(paramSpec, BaseUtils.hexStringToByteArray(a_pri));
        PrivateKey privateKey = kf.generatePrivate(privateSpec);
        boolean clearHighBit = curveName.equals("X25519");

        //System.out.println("Clear high bit = " + clearHighBit);

        KeySpec publicSpec = new XECPublicKeySpec(paramSpec,
                hexStringToBigInteger(clearHighBit, b_pub));
        //System.out.println("String Pub = " + b_pub);
        //System.out.println("Hex String Clean Highbit = " +byteArrayToHexString(hexStringToBigInteger(clearHighBit, b_pub).toByteArray()));

        PublicKey publicKey = kf.generatePublic(publicSpec);

        byte[] encodedPrivateKey = privateKey.getEncoded();
        System.out.println("Encoded private: " + byteArrayToHexString(encodedPrivateKey));
        byte[] encodedPublicKey = publicKey.getEncoded();
        System.out.println("Encoded public: " + byteArrayToHexString(encodedPublicKey));

        KeyAgreement ka = KeyAgreement.getInstance("XDH", getProviderName());
        //System.out.println("1");
        ka.init(privateKey);
        //System.out.println("2");
        ka.doPhase(publicKey, true);
        //System.out.println("3");

        byte[] sharedSecret = ka.generateSecret();
        //System.out.println("4");
        byte[] expectedResult = BaseUtils.hexStringToByteArray(result);
        //System.out.println("5");
        if (!Arrays.equals(sharedSecret, expectedResult)) {
            //System.out.println("6");
            throw new RuntimeException(
                    "fail: expected=" + result + ", actual=" + byteArrayToHexString(sharedSecret));
        }
        assertTrue(true);
    }

    /*
     * Ensure that SunEC rejects parameters/points for the wrong curve
     * when the algorithm ID for a specific curve is specified.
     */
    private void runCurveMixTest() throws Exception {
        runCurveMixTest("X25519", 448);
        runCurveMixTest("X25519", "X448");
        runCurveMixTest("X448", 255);
        runCurveMixTest("X448", "X25519");
    }

    private void runCurveMixTest(String name, Object param) throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(name, getProviderName());

        try {
            if (param instanceof Integer) {
                kpg.initialize((Integer) param);
            } else if (param instanceof String) {
                kpg.initialize(new NamedParameterSpec((String) param));
            }
            throw new RuntimeException(
                    name + " KeyPairGenerator accepted " + param.toString() + " parameters");
        } catch (InvalidParameterException ex) {
            // expected
        } catch (InvalidAlgorithmParameterException e) {
            // expected
        }

        // the rest of the test uses the parameter as an algorithm name to
        // produce keys
        if (param instanceof Integer) {
            return;
        }
        String otherName = (String) param;
        //System.out.println("Other name = "+otherName);
        //System.out.println("Name = "+name);

        KeyPairGenerator otherKpg = KeyPairGenerator.getInstance(otherName, getProviderName());
        KeyPair otherKp = otherKpg.generateKeyPair();

        // ensure the KeyFactory rejects incorrect keys
        KeyFactory kf = KeyFactory.getInstance(name, getProviderName());
        try {
            kf.getKeySpec(otherKp.getPublic(), XECPublicKeySpec.class);
            throw new RuntimeException(name + " KeyFactory accepted " + param.toString() + " key");
        } catch (InvalidKeySpecException ex) {
            // expected
        }
        try {
            kf.getKeySpec(otherKp.getPrivate(), XECPrivateKeySpec.class);
            throw new RuntimeException(name + " KeyFactory accepted " + param.toString() + " key");
        } catch (InvalidKeySpecException ex) {
            // expected
        }

        try {
            kf.translateKey(otherKp.getPublic());
            throw new RuntimeException(name + " KeyFactory accepted " + param.toString() + " key");
        } catch (InvalidKeyException ex) {
            // expected
        }
        try {
            kf.translateKey(otherKp.getPrivate());
            throw new RuntimeException(name + " KeyFactory accepted " + param.toString() + " key");
        } catch (InvalidKeyException ex) {
            // expected
        }

        KeyFactory otherKf = KeyFactory.getInstance(otherName, getProviderName());
        XECPublicKeySpec otherPubSpec = otherKf.getKeySpec(otherKp.getPublic(),
                XECPublicKeySpec.class);
        try {
            kf.generatePublic(otherPubSpec);
            throw new RuntimeException(name + " KeyFactory accepted " + param.toString() + " key");
        } catch (InvalidKeySpecException ex) {
            // expected
        }
        XECPrivateKeySpec otherPriSpec = otherKf.getKeySpec(otherKp.getPrivate(),
                XECPrivateKeySpec.class);
        try {
            kf.generatePrivate(otherPriSpec);
            throw new RuntimeException(name + " KeyFactory accepted " + param.toString() + " key");
        } catch (InvalidKeySpecException ex) {
            // expected
        }

        // ensure the KeyAgreement rejects incorrect keys
        KeyAgreement ka = KeyAgreement.getInstance(name, getProviderName());
        try {
            ka.init(otherKp.getPrivate());
            throw new RuntimeException(
                    name + " KeyAgreement accepted " + param.toString() + " key");
        } catch (InvalidKeyException ex) {
            // expected
        }
        KeyPair kp = kpg.generateKeyPair();
        ka.init(kp.getPrivate());
        try {
            // This should always be rejected because it doesn't match the key
            // passed to init, but it is tested here for good measure.
            ka.doPhase(otherKp.getPublic(), true);
            throw new RuntimeException(
                    name + " KeyAgreement accepted " + param.toString() + " key");
        } catch (InvalidKeyException ex) {
            // expected
        }
        assertTrue(true);
    }

    // Convert from a byte array to a hexadecimal representation as a string.
    public static String byteArrayToHexString(byte[] arr) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < arr.length; ++i) {
            byte curVal = arr[i];
            result.append(Character.forDigit(curVal >> 4 & 0xF, 16));
            result.append(Character.forDigit(curVal & 0xF, 16));
        }
        return result.toString();
    }

    // Expand a single byte to a byte array
    public static byte[] byteToByteArray(byte v, int length) {
        byte[] result = new byte[length];
        result[0] = v;
        return result;
    }

    /*
     * Convert a hexadecimal string to the corresponding little-ending number
     * as a BigInteger. The clearHighBit argument determines whether the most
     * significant bit of the highest byte should be set to 0 in the result.
     */
    public static BigInteger hexStringToBigInteger(boolean clearHighBit, String str) {
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < str.length() / 2; i++) {
            int curVal = Character.digit(str.charAt(2 * i), 16);
            curVal <<= 4;
            curVal += Character.digit(str.charAt(2 * i + 1), 16);
            if (clearHighBit && i == str.length() / 2 - 1) {
                curVal &= 0x7F;
            }
            result = result.add(BigInteger.valueOf(curVal).shiftLeft(8 * i));
        }
        return result;
    }

    private static void reverseByteArray(byte[] arr) throws IOException {
        for (int i = 0; i < arr.length / 2; i++) {
            byte temp = arr[i];
            arr[i] = arr[arr.length - 1 - i];
            arr[arr.length - 1 - i] = temp;
        }
    }
}

