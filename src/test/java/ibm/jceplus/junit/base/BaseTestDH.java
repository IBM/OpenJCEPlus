/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.List;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestDH extends BaseTestJunit5 {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    DHParameterSpec algParameterSpec_1024, algParameterSpec_2048, algParameterSpec_3072,
            algParameterSpec_4096, algParameterSpec_6144, algParameterSpec_8192;

    KeyPairGenerator kpgA = null;
    KeyPairGenerator kpgB = null;

    KeyPair keyPairA_1024, keyPairA_2048, keyPairA_3072, keyPairA_4096, keyPairA_6144,
            keyPairA_8192;
    KeyPair keyPairB_1024, keyPairB_2048, keyPairB_3072, keyPairB_4096, keyPairB_6144,
            keyPairB_8192;

    private boolean isMulti = false;

    @BeforeEach
    public void setUp() throws Exception {
        generateParameters(getProviderName());
    }

    public boolean isMulti() {
        return isMulti;
    }

    public void setMulti(boolean isMulti) {
        this.isMulti = isMulti;
    }

    boolean generated = false;

    synchronized void generateParameters(String provider_name) {
        if (generated)
            return;
        try {
            System.out.println("Provider name = " + provider_name);
            if (!provider_name.equals("OpenJCEPlusFIPS")) {
                algParameterSpec_1024 = generateDHParameters(1024);
            }
            algParameterSpec_2048 = generateDHParameters(2048);
            algParameterSpec_3072 = generateDHParameters(3072);
            algParameterSpec_4096 = generateDHParameters(4096);
            algParameterSpec_6144 = generateDHParameters(6144);
            algParameterSpec_8192 = generateDHParameters(8192);

            kpgA = KeyPairGenerator.getInstance("DH", provider_name);
            if (!provider_name.equals("OpenJCEPlusFIPS")) {
                kpgA.initialize(algParameterSpec_1024);
                keyPairA_1024 = kpgA.generateKeyPair();
            }
            kpgA.initialize(algParameterSpec_2048);
            keyPairA_2048 = kpgA.generateKeyPair();
            kpgA.initialize(algParameterSpec_3072);
            keyPairA_3072 = kpgA.generateKeyPair();
            kpgA.initialize(algParameterSpec_4096);
            keyPairA_4096 = kpgA.generateKeyPair();
            kpgA.initialize(algParameterSpec_6144);
            keyPairA_6144 = kpgA.generateKeyPair();
            kpgA.initialize(algParameterSpec_8192);
            keyPairA_8192 = kpgA.generateKeyPair();

            kpgB = KeyPairGenerator.getInstance("DH", provider_name);
            if (!provider_name.equals("OpenJCEPlusFIPS")) {
                kpgB.initialize(algParameterSpec_1024);
                keyPairB_1024 = kpgB.generateKeyPair();
            }
            kpgB.initialize(algParameterSpec_2048);
            keyPairB_2048 = kpgB.generateKeyPair();
            kpgB.initialize(algParameterSpec_3072);
            keyPairB_3072 = kpgB.generateKeyPair();
            kpgB.initialize(algParameterSpec_4096);
            keyPairB_4096 = kpgB.generateKeyPair();
            kpgB.initialize(algParameterSpec_6144);
            keyPairB_6144 = kpgB.generateKeyPair();
            kpgB.initialize(algParameterSpec_8192);
            keyPairB_8192 = kpgB.generateKeyPair();
            generated = true;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    /**
     * Basic DH example
     *
     * @throws Exception
     */
    @Test
    public void testDHKeyPairGeneratorGetAlgorithm() throws Exception {
        String algorithms[] = {"DiffieHellman", "DH", "1.2.840.113549.1.3.1",
                "OID.1.2.840.113549.1.3.1"};
        for (int i = 0; i < algorithms.length; i++) {
            assertTrue(KeyPairGenerator.getInstance(algorithms[i], getProviderName()).getAlgorithm()
                    .equals(algorithms[i]));
        }
    }

    @Test
    public void testDH_1024() throws Exception {

        if (!getProviderName().equals("OpenJCEPlusFIPS")) {

            DHParameterSpec dhps = generateDHParameters(1024);
            compute_dh_key("1024", dhps);
            if (isMulti)
                compute_dh_key_with_global_key("1024", algParameterSpec_1024);
        } else {
            assertTrue(true);
        }
    }

    @Test
    public void testDH_2048() throws Exception {
        //System.out.println ("Testing DH 2048");

        DHParameterSpec dhps = generateDHParameters(2048);
        compute_dh_key("2048", dhps);
        if (isMulti)
            compute_dh_key_with_global_key("2048", algParameterSpec_2048);

    }

    @Test
    public void testDH_3072() throws Exception {
        //System.out.println ("Testing DH 3072");

        DHParameterSpec dhps = generateDHParameters(3072);
        compute_dh_key("3072", dhps);
        if (isMulti)
            compute_dh_key_with_global_key("3072", algParameterSpec_3072);

    }

    @Test
    public void testDH_4096() throws Exception {
        //System.out.println ("Testing DH 4096");

        DHParameterSpec dhps = generateDHParameters(4096);
        compute_dh_key("4096", dhps);
        if (isMulti)
            compute_dh_key_with_global_key("4096", algParameterSpec_4096);

    }

    @Test
    public void testDH_6144() throws Exception {
        //System.out.println ("Testing DH 6144");

        DHParameterSpec dhps = generateDHParameters(6144);
        compute_dh_key("6144", dhps);
        if (isMulti)
            compute_dh_key_with_global_key("6144", algParameterSpec_6144);

    }

    @Test
    public void testDH_8192() throws Exception {
        //System.out.println ("Testing DH 8192");

        DHParameterSpec dhps = generateDHParameters(8192);
        compute_dh_key("8192", dhps);
        if (isMulti)
            compute_dh_key_with_global_key("8192", algParameterSpec_8192);

    }

    @Test
    public void testDH_DHSpec() throws Exception {

        String methodId = "DHParamSpec";

        if (!getProviderName().equals("OpenJCEPlusFIPS")) {
            DHParameterSpec dhParamSpec = generateDHParameters(1024);

            compute_dh_key(methodId, dhParamSpec);
        } else {
            assertTrue(true);
        }

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

    void compute_dh_key(String idString, AlgorithmParameterSpec algParameterSpec)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchProviderException, InvalidKeyException {
        final String methodName = "compute_dh_key" + "_" + idString;

        KeyPairGenerator kpgA = null;
        try {
            kpgA = KeyPairGenerator.getInstance("DH", getProviderName());
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
            keyAgreeA = KeyAgreement.getInstance("DH", getProviderName());
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
            kpgB = KeyPairGenerator.getInstance("DH", getProviderName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }

        try {
            kpgB.initialize(algParameterSpec);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw e;
        }

        KeyPair keyPairB = kpgB.generateKeyPair();


        KeyAgreement keyAgreeB = null;
        try {
            keyAgreeB = KeyAgreement.getInstance("DH", getProviderName());
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


        boolean assertFlag = Arrays.equals(sharedSecretA, sharedSecretB);
        if (!assertFlag) {

            System.out.println(
                    methodName + " sharedSecretA = " + BaseUtils.bytesToHex(sharedSecretA));
            System.out.println(
                    methodName + " sharedSecretB = " + BaseUtils.bytesToHex(sharedSecretB));

            System.out.println(
                    "KeyPairB.privKey=" + BaseUtils.bytesToHex(keyPairB.getPrivate().getEncoded()));
            System.out.println("KeyPairB.publicKey="
                    + BaseUtils.bytesToHex(keyPairB.getPublic().getEncoded()));
            System.out.println(
                    "KeyPairA.privKey=" + BaseUtils.bytesToHex(keyPairA.getPrivate().getEncoded()));
            System.out.println("KeyPairA.publicKey="
                    + BaseUtils.bytesToHex(keyPairA.getPublic().getEncoded()));

        }
        assertTrue(assertFlag);

    }

    private DHParameterSpec generateDHParameters(int size) throws Exception {

        AlgorithmParameterGenerator algParamGen = AlgorithmParameterGenerator.getInstance("DH",
                getProviderName());
        algParamGen.init(size);
        AlgorithmParameters algParams = algParamGen.generateParameters();
        DHParameterSpec dhps = algParams.getParameterSpec(DHParameterSpec.class);
        return dhps;

    }

    void compute_dh_key_with_global_key(String idString, AlgorithmParameterSpec algParameterSpec)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchProviderException, InvalidKeyException {
        final String methodName = "compute_dh_key_with_global_key" + "_" + idString;

        KeyPair keyPairA = null, keyPairB = null;
        switch (idString) {
            case "1024":
                keyPairA = keyPairA_1024;
                keyPairB = keyPairB_1024;
                break;

            case "2048":
                keyPairA = keyPairA_2048;
                keyPairB = keyPairB_2048;
                break;

            case "3072":
                keyPairA = keyPairA_3072;
                keyPairB = keyPairB_3072;
                break;

            case "4096":
                keyPairA = keyPairA_4096;
                keyPairB = keyPairB_4096;
                break;

            case "6144":
                keyPairA = keyPairA_6144;
                keyPairB = keyPairB_6144;
                break;

            case "8192":
                keyPairA = keyPairA_8192;
                keyPairB = keyPairB_8192;
                break;
        }

        // set up A
        KeyAgreement keyAgreeA = null;
        try {
            keyAgreeA = KeyAgreement.getInstance("DH", getProviderName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }
        // Two party agreement A
        try {
            keyAgreeA.init(keyPairA.getPrivate());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw e;
        }
        // set up B
        KeyAgreement keyAgreeB = null;
        try {
            keyAgreeB = KeyAgreement.getInstance("DH", getProviderName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }
        // Two party agreement B
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

        boolean assertFlag = Arrays.equals(sharedSecretA, sharedSecretB);
        if (!assertFlag) {

            System.out.println(
                    methodName + " sharedSecretA = " + BaseUtils.bytesToHex(sharedSecretA));
            System.out.println(
                    methodName + " sharedSecretB = " + BaseUtils.bytesToHex(sharedSecretB));

            System.out.println(
                    "KeyPairB.privKey=" + BaseUtils.bytesToHex(keyPairB.getPrivate().getEncoded()));
            System.out.println("KeyPairB.publicKey="
                    + BaseUtils.bytesToHex(keyPairB.getPublic().getEncoded()));
            System.out.println(
                    "KeyPairA.privKey=" + BaseUtils.bytesToHex(keyPairA.getPrivate().getEncoded()));
            System.out.println("KeyPairA.publicKey="
                    + BaseUtils.bytesToHex(keyPairA.getPublic().getEncoded()));

        }
        assertTrue(assertFlag);

    }
}
