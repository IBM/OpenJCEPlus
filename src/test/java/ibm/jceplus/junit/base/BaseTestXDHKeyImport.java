/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class BaseTestXDHKeyImport extends ibm.jceplus.junit.base.BaseTest {

    public BaseTestXDHKeyImport(String providerName) {
        super(providerName);
    }

    public void setUp() throws Exception {}

    public void tearDown() throws Exception {}

    public void testCreateKeyPairNamedParamImport_X25519() throws Exception {
        createKeyPairNamedParamImport("X25519");
        createKeyPairXDHParamImport("X25519");
        createKeyPairLocalParamImport("X25519");
    }

    public void testCreateKeyPairNamedParamImport_X448() throws Exception {
        createKeyPairNamedParamImport("X448");
        createKeyPairXDHParamImport("X448");
        createKeyPairLocalParamImport("X448");
    }
    //    public void testCreateKeyPairNamedParamImport_FFDHE2048() throws Exception {
    //        createKeyPairNamedParamImport("FFDHE2048");
    //    }
    //    public void testCreateKeyPairNamedParamImport_FFDHE3072() throws Exception {
    //        createKeyPairNamedParamImport("FFDHE3072");
    //    }
    //    public void testCreateKeyPairNamedParamImport_FFDHE4096() throws Exception {
    //        createKeyPairNamedParamImport("FFDHE4096");
    //    }
    //    public void testCreateKeyPairNamedParamImport_FFDHE6144() throws Exception {
    //        createKeyPairNamedParamImport("FFDHE6144");
    //    }
    //    public void testCreateKeyPairNamedParamImport_FFDHE8192() throws Exception {
    //        createKeyPairNamedParamImport("FFDHE8192");
    //    }

    /**
     * Generate a KeyPair using NamedParam, convert the keys to 
     * PKCS8EncodedKeySpec/X509EncodedKeySpec, and then import 
     * them
     * (this tests constructing the keys from encoded byte[])
     *
     * @throws Exception
     */
    public void createKeyPairNamedParamImport(String alg) throws Exception {
        //final String methodName = "testCreateKeyPairNamedParamImport";

        NamedParameterSpec nps = new NamedParameterSpec(alg);
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("XDH", providerName);

        keyPairGen.initialize(nps);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        byte[] pubKeyBytes = publicKey.getEncoded();
        byte[] privKeyBytes = privateKey.getEncoded();

        // Uncomment and run asn1dec.exe
        // System.out.println (methodName + " pubKeyBytes length=" +
        // pubKeyBytes.length);
        // System.out.println (methodName + " publicKeyBytes = " +
        // BaseUtils.bytesToHex(pubKeyBytes));
        // System.out.println (methodName + " privKeyBytes length=" +
        // privKeyBytes.length);
        // System.out.println (methodName + " privKeyBytes = " +
        // BaseUtils.bytesToHex(privKeyBytes));

        KeyFactory keyFactory = KeyFactory.getInstance("XDH", providerName);
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);
        PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubKeyBytes);
        PublicKey publicKey2 = keyFactory.generatePublic(publicKeySpec);

        // The original and new keys are the same
        boolean same = privateKey.equals(privateKey2);
        assertTrue(same);
        same = publicKey.equals(publicKey2);
        assertTrue(same);
    }

    /**
     * Use key params from OpenJDK, and make sure we produce the same encoded key as in OpenJDK.
     * <p>
     * Known answers were obtained from Java 17 (public and private key were generated and the params were extracted from them).
     * <p>
     * These values are known to be different from Java 17+ due to an optional scalar, more information below.
     * <p>
     * RFC 2459 section 4.1.1.2 defines an AlgorithmIdentifier as follows:
     * <pre>
     * AlgorithmIdentifier  ::=  SEQUENCE  {
     *  algorithm               OBJECT IDENTIFIER,
     *  parameters              ANY DEFINED BY algorithm OPTIONAL  }
     * </pre>
     * The `parameters` specified in this case are defined as OPTIONAL.
     * <p>
     * These values in this test are different between Java 11 and Java 17 due to the subtle difference 
     * in the DER representation of the values.
     * <p>
     * Java 11 represents the DER encoding as follows for the X25519 test value below:
     * <p>
     * MCwwBwYDK2VuBQADIQCZTaUdgOwpJrtig+RR47FrN6P2xZv2baFhscSXq4gjAQ==
     * <pre>
     *     SEQUENCE {
     *        SEQUENCE {
     *           OBJECTIDENTIFIER 1.3.101.110
     *           NULL
     *        }
     *        BITSTRING 0x994da51d80ec2926bb6283e451e3b16b37a3f6c59bf66da161b1c497ab882301 : 0 unused bit(s)
     *     }
     * </pre>
     * Notice the optional `NULL` in the nested SEQUENCE. This NULL is an optional parameter as per the RFC so
     * seems to be left up for interpretation.
     * <p>
     * Java 17 however represents the DER encoding as follows for the same BITSTRING value:
     * <p>
     * MCowBQYDK2VuAyEAmU2lHYDsKSa7YoPkUeOxazej9sWb9m2hYbHEl6uIIwE=
     * <pre>
     *     SEQUENCE {
     *        SEQUENCE {
     *           OBJECTIDENTIFIER 1.3.101.110
     *        }
     *        BITSTRING 0x994da51d80ec2926bb6283e451e3b16b37a3f6c59bf66da161b1c497ab882301 : 0 unused bit(s)
     *     }
     * </pre>
     * Notice there is no `NULL` value for the nested sequence for the OPTIONAL `parameters` value.
     * 
     * @throws Exception thrown when alg is not `X25519` or `X448`.
     * @param alg The algorithm to test either `X25519` or `X448` value are accepted.
     *
     */
    public void createKeyPairXDHParamImport(String alg) throws Exception {
        //final String methodName = "testCreateKeyPairXDHParamImport";

        BigInteger u;
        byte[] scalar;
        byte[] actualPbk;
        byte[] actualPvk;
        if ("X25519".equals(alg)) {
            u = new BigInteger(
                    "515095759487624245475052955143775821008860566299846242602604658885545774489");
            scalar = Base64.getDecoder().decode("RtcJeC6VA0w1s2ly58eimwgmjNnIvdBQ0WwXodcOKx0=");
            actualPbk = Base64.getDecoder()
                    .decode("MCowBQYDK2VuAyEAmU2lHYDsKSa7YoPkUeOxazej9sWb9m2hYbHEl6uIIwE=");
            actualPvk = Base64.getDecoder()
                    .decode("MC4CAQAwBQYDK2VuBCIEIEbXCXgulQNMNbNpcufHopsIJozZyL3QUNFsF6HXDisd");
        } else if ("X448".equals(alg)) {
            u = new BigInteger(
                    "107118908792121879403264595066242232572753965363231309947133508353953425798840260547451796239712078839812016803162450215013342651330517");
            scalar = Base64.getDecoder().decode(
                    "WoCM2tS1l/nYi6+GD+j3iiSVWsL3wFEOz+wBqB/Jd+M0OeZQX4vUqFddaiy4fkGKOU/59t3qGWo=");
            actualPbk = Base64.getDecoder().decode(
                    "MEIwBQYDK2VvAzkA1a+7mFk5GWcGvzEHTcFVNsM8G7eeuxKAvBDiwGkqEB0GcyZOEtPg7slPdRKo6vL8PEbBcHx2uiU=");
            actualPvk = Base64.getDecoder().decode(
                    "MEYCAQAwBQYDK2VvBDoEOFqAjNrUtZf52Iuvhg/o94oklVrC98BRDs/sAagfyXfjNDnmUF+L1KhXXWosuH5BijlP+fbd6hlq");
        } else {
            throw new InvalidParameterException(alg + " is not supported");
        }

        NamedParameterSpec paramSpec = new NamedParameterSpec(alg);
        KeyFactory kf = KeyFactory.getInstance("XDH");

        XECPublicKeySpec xdhPublic = new XECPublicKeySpec(paramSpec, u);
        XECPrivateKeySpec xdhPrivate = new XECPrivateKeySpec(paramSpec, scalar);

        PublicKey pbk = kf.generatePublic(xdhPublic);
        PrivateKey pvk = kf.generatePrivate(xdhPrivate);

        assertTrue(Arrays.equals(pbk.getEncoded(), actualPbk));
        assertTrue(Arrays.equals(pvk.getEncoded(), actualPvk));
    }

    /**
     * Generate a KeyPair using NamedParam, convert the keys to 
     * XECPrivateKeySpec/XECPublicKeySpec, and then import 
     * them
     * (this tests creating the keys from parameters)
     *
     * @throws Exception
     */
    void createKeyPairLocalParamImport(String alg) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg);
        //        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
        NamedParameterSpec paramSpec = new NamedParameterSpec(alg);
        System.out.println("Alg = " + alg);
        kpg.initialize(paramSpec);

        KeyPair kp = kpg.generateKeyPair();
        PrivateKey pvk = kp.getPrivate();
        PublicKey pbk = kp.getPublic();

        KeyFactory kf = KeyFactory.getInstance(alg);
        //        KeyFactory kf = KeyFactory.getInstance("XDH");
        XECPublicKeySpec xdhPublic = kf.getKeySpec(kp.getPublic(), XECPublicKeySpec.class);
        XECPrivateKeySpec xdhPrivate = kf.getKeySpec(kp.getPrivate(), XECPrivateKeySpec.class);

        // Get params and use them to make new specs
        BigInteger u = xdhPublic.getU();
        byte[] scalar = xdhPrivate.getScalar();

        xdhPublic = new XECPublicKeySpec(paramSpec, u);
        xdhPrivate = new XECPrivateKeySpec(paramSpec, scalar);

        // Use new specs to produce keys
        PublicKey pbk2 = kf.generatePublic(xdhPublic);
        PrivateKey pvk2 = kf.generatePrivate(xdhPrivate);

        System.out.println(" pbk =" + BaseUtils.bytesToHex(pbk2.getEncoded()));
        System.out.println(" pbk2 = " + BaseUtils.bytesToHex(pbk.getEncoded()));

        // Verify that keys match
        assertTrue(Arrays.equals(pbk.getEncoded(), pbk2.getEncoded()));
        assertTrue(Arrays.equals(pvk.getEncoded(), pvk2.getEncoded()));
    }
}

