/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestRSAPSSInterop2 extends BaseTestJunit5 {

    String signingProvidersSignatureAlgorithmName = null;
    String verifyingProvidersSignatureAlgorithmName = null;
    //IBMJCE     ==> "RSAPSS"
    //OpenJCEPlus ==> "RSAPSS"
    //SunRsaSign ==> "RSASSA-PSS"

    String signingProviderName = null;
    String verifyingProviderName = null;

    static final byte[] dataToBeSignedShort = "a".getBytes();
    static final byte[] dataToBeSignedMedium = "this is text to test the RSAPSS Signature xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            .getBytes();
    static final byte[] dataToBeSignedLong = "this is text to test the RSAPSS Signature xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            .getBytes();

    static KeyPairGenerator rsaKeyPairGen = null;

    static KeyPair rsaKeyPair_OpenJCEPlus[] = new KeyPair[6];
    static KeyPair rsaKeyPair_SunRsaSign[] = new KeyPair[6];
    static KeyPair rsaKeyPair_OpenJCEPlusFIPS[] = new KeyPair[6];

    static PSSParameterSpec pssParameterSpec = null;

    static int testCaseNumber = 1;

    Provider provider = null;
    static boolean printJunitTrace = false;

    @BeforeEach
    public void setUp() throws Exception {

        if (printJunitTrace)
            System.out.println(
                    "======================================================================================");
        if (printJunitTrace)
            System.out.println(
                    "===================== BEGIN TEST CASE BaseTestRSAPSSInterop2 =========================");
        if (printJunitTrace)
            System.out.println(
                    "======================================================================================");

        signingProviderName = "SunRsaSign";
        verifyingProviderName = "OpenJCEPlus";

        // Add the OpenJCEPlus provider to the provider's list
        provider = new com.ibm.crypto.plus.provider.OpenJCEPlus();
        try {
            Security.insertProviderAt(provider, 3);
        } catch (Exception ex) {
            if (printJunitTrace)
                System.out.println(
                        "Failed to create the OpenJCEPlus provider.  The following exception was thrown.");
            ex.printStackTrace();
        }

        java.security.Provider[] providers = Security.getProviders();
        if (printJunitTrace)
            System.out.println("The providers in the providers list are:");
        for (int i = 0; i < providers.length; ++i) {
            if (printJunitTrace)
                System.out.println("Provider #" + i + " = " + providers[i].toString());
            if (printJunitTrace)
                System.out.println();
        }

        if (signingProviderName.equalsIgnoreCase("SunRsaSign")) {
            signingProvidersSignatureAlgorithmName = "RSASSA-PSS";
            verifyingProvidersSignatureAlgorithmName = "RSASSA-PSS";
        } else if (signingProviderName.equalsIgnoreCase("OpenJCEPlus")) {
            signingProvidersSignatureAlgorithmName = "RSASSA-PSS";
            verifyingProvidersSignatureAlgorithmName = "RSASSA-PSS";
        } else if (signingProviderName.equalsIgnoreCase("OpenJCEPlusFIPS")) {
            signingProvidersSignatureAlgorithmName = "RSASSA-PSS";
            verifyingProvidersSignatureAlgorithmName = "RSASSA-PSS";
        }

        if (printJunitTrace)
            System.out.println(
                    "BaseTestRSAPSSInterop2.java:  setup():  Following the call to setUp(), signingProviderName   = "
                            + signingProviderName);
        if (printJunitTrace)
            System.out.println(
                    "BaseTestRSAPSSInterop2.java:  setup():  Following the call to setUp(), verifyingProviderName = "
                            + verifyingProviderName);

        //================================================================

        if (signingProviderName.equalsIgnoreCase("OpenJCEPlus")) {
            // KeyPairs for OpenJCEPlus
            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "OpenJCEPlus");
            rsaKeyPairGen.initialize(512, null);
            rsaKeyPair_OpenJCEPlus[0] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_OpenJCEPlus[0] = RSA 512

            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "OpenJCEPlus");
            rsaKeyPairGen.initialize(1024, null);
            rsaKeyPair_OpenJCEPlus[1] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_OpenJCEPlus[1] = RSA 1024

            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "OpenJCEPlus");
            rsaKeyPairGen.initialize(2048, null);
            rsaKeyPair_OpenJCEPlus[2] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_OpenJCEPlus[2] = RSA 2048

            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "OpenJCEPlus");
            rsaKeyPairGen.initialize(3072, null);
            rsaKeyPair_OpenJCEPlus[3] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_OpenJCEPlus[3] = RSA 3072

            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "OpenJCEPlus");
            rsaKeyPairGen.initialize(4096, null);
            rsaKeyPair_OpenJCEPlus[4] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_OpenJCEPlus[4] = RSA 4096

            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "OpenJCEPlus");
            rsaKeyPairGen.initialize(5120, null);
            rsaKeyPair_OpenJCEPlus[5] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_OpenJCEPlus[5] = RSA 5120
        }

        //================================================================

        if (signingProviderName.equalsIgnoreCase("SunRsaSign")) {
            // KeyPairs for SunRsaSign
            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
            rsaKeyPairGen.initialize(512, null);
            rsaKeyPair_SunRsaSign[0] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_SunRsaSign[0] = RSA 512

            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
            rsaKeyPairGen.initialize(1024, null);
            rsaKeyPair_SunRsaSign[1] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_SunRsaSign[1] = RSA 1024

            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
            rsaKeyPairGen.initialize(2048, null);
            rsaKeyPair_SunRsaSign[2] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_SunRsaSign[2] = RSA 2048

            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
            rsaKeyPairGen.initialize(3072, null);
            rsaKeyPair_SunRsaSign[3] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_SunRsaSign[3] = RSA 3072

            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
            rsaKeyPairGen.initialize(4096, null);
            rsaKeyPair_SunRsaSign[4] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_SunRsaSign[4] = RSA 4096

            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
            rsaKeyPairGen.initialize(5120, null);
            rsaKeyPair_SunRsaSign[5] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_SunRsaSign[5] = RSA 5120
        }

        //================================================================

        if (signingProviderName.equalsIgnoreCase("OpenJCEPlusFIPS")) {
            // KeyPairs for OpenJCEPlusFIPS
            // rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "OpenJCEPlusFIPS");
            //rsaKeyPairGen.initialize(512, null);
            //rsaKeyPair_OpenJCEPlusFIPS[0] = rsaKeyPairGen.generateKeyPair();               // rsaKeyPair_OpenJCEPlusFIPS[0] = RSA 512

            //rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "OpenJCEPlusFIPS");
            //rsaKeyPairGen.initialize(1024, null);
            //rsaKeyPair_OpenJCEPlusFIPS[1] = rsaKeyPairGen.generateKeyPair();               // rsaKeyPair_OpenJCEPlusFIPS[1] = RSA 1024

            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "OpenJCEPlusFIPS");
            rsaKeyPairGen.initialize(2048, null);
            rsaKeyPair_OpenJCEPlusFIPS[2] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_OpenJCEPlusFIPS[2] = RSA 2048

            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "OpenJCEPlusFIPS");
            rsaKeyPairGen.initialize(3072, null);
            rsaKeyPair_OpenJCEPlusFIPS[3] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_OpenJCEPlusFIPS[3] = RSA 3072

            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "OpenJCEPlusFIPS");
            rsaKeyPairGen.initialize(4096, null);
            rsaKeyPair_OpenJCEPlusFIPS[4] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_OpenJCEPlusFIPS[4] = RSA 4096

            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "OpenJCEPlusFIPS");
            rsaKeyPairGen.initialize(5120, null);
            rsaKeyPair_OpenJCEPlusFIPS[5] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_OpenJCEPlusFIPS[5] = RSA 5120
        }

        //================================================================

    }



    //==================================================================================================================
    //   BEGINNING OF RSA-PSS SIGNATURE TESTS
    //==================================================================================================================

    @Test
    public void testRSAPSS() throws Exception {

        KeyPair rsaKeyPair = null;
        byte[] dataToBeSigned;

        if (printJunitTrace)
            System.out.println(
                    "================  BEGINNING OF testRSAPSS()  ================================");

        // Cannot do RSA 512 key size for SHA384 and others  due to the following exception from SunRSASign
        //   testRSAPSS(ibm.jceplus.junit.openjceplus.TestRSAPSSInterop2)java.security.InvalidKeyException: java.security.SignatureException: Key is too short, need min 70 

        //OpenJCEPlusFIPS and SunRsaSign does not support 512
        for (int ii = 1; ii <= 5; ii++) { // For each RSA key size
            if (signingProviderName.equalsIgnoreCase("OpenJCEPlus")) {
                if (ii == 0) {
                    rsaKeyPair = rsaKeyPair_OpenJCEPlus[0]; // RSA keylength 512
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_OpenJCEPlus[0] ");
                } else if (ii == 1) {
                    rsaKeyPair = rsaKeyPair_OpenJCEPlus[1]; // RSA keylength 1024
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_OpenJCEPlus[1] ");
                } else if (ii == 2) {
                    rsaKeyPair = rsaKeyPair_OpenJCEPlus[2]; // RSA keylength 2048
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_OpenJCEPlus[2] ");
                } else if (ii == 3) {
                    rsaKeyPair = rsaKeyPair_OpenJCEPlus[3]; // RSA keylength 3072
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_OpenJCEPlus[3] ");
                } else if (ii == 4) {
                    rsaKeyPair = rsaKeyPair_OpenJCEPlus[4]; // RSA keylength 4096
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_OpenJCEPlus[4] ");
                } else if (ii == 5) {
                    rsaKeyPair = rsaKeyPair_OpenJCEPlus[5]; // RSA keylength 5120
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_OpenJCEPlus[5] ");
                }

            } else if (signingProviderName.equalsIgnoreCase("SunRsaSign")) {
                if (ii == 0) {
                    rsaKeyPair = rsaKeyPair_SunRsaSign[0]; // RSA keylength 512
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_SunRsaSign[0] ");
                } else if (ii == 1) {
                    rsaKeyPair = rsaKeyPair_SunRsaSign[1]; // RSA keylength 1024
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_SunRsaSign[1] ");
                } else if (ii == 2) {
                    rsaKeyPair = rsaKeyPair_SunRsaSign[2]; // RSA keylength 2048
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_SunRsaSign[2] ");
                } else if (ii == 3) {
                    rsaKeyPair = rsaKeyPair_SunRsaSign[3]; // RSA keylength 3072
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_SunRsaSign[3] ");
                } else if (ii == 4) {
                    rsaKeyPair = rsaKeyPair_SunRsaSign[4]; // RSA keylength 4096
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_SunRsaSign[4] ");
                } else if (ii == 5) {
                    rsaKeyPair = rsaKeyPair_SunRsaSign[5]; // RSA keylength 5120
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_SunRsaSign[5] ");
                }

            } else if (signingProviderName.equalsIgnoreCase("OpenJCEPlusFIPS")) {
                if (ii == 0) {
                    rsaKeyPair = rsaKeyPair_OpenJCEPlusFIPS[0]; // RSA keylength 512
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_OpenJCEPlusFIPS[0] ");
                } else if (ii == 1) {
                    rsaKeyPair = rsaKeyPair_OpenJCEPlusFIPS[1]; // RSA keylength 1024
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_OpenJCEPlusFIPS[1] ");
                } else if (ii == 2) {
                    rsaKeyPair = rsaKeyPair_OpenJCEPlusFIPS[2]; // RSA keylength 2048
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_OpenJCEPlusFIPS[2] ");
                } else if (ii == 3) {
                    rsaKeyPair = rsaKeyPair_OpenJCEPlusFIPS[3]; // RSA keylength 3072
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_OpenJCEPlusFIPS[3] ");
                } else if (ii == 4) {
                    rsaKeyPair = rsaKeyPair_OpenJCEPlusFIPS[4]; // RSA keylength 4096
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_OpenJCEPlusFIPS[4] ");
                } else if (ii == 5) {
                    rsaKeyPair = rsaKeyPair_OpenJCEPlusFIPS[5]; // RSA keylength 5120
                    if (printJunitTrace)
                        System.out.println(
                                "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_OpenJCEPlusFIPS[5] ");
                }
            }

            for (int jj = 0; jj < 3; jj++) { // For each dataToBeSigned string (differing lengths)

                if (jj == 0) {
                    dataToBeSigned = dataToBeSignedShort;
                } else if (jj == 1) {
                    dataToBeSigned = dataToBeSignedMedium;
                } else if (jj == 2) {
                    dataToBeSigned = dataToBeSignedLong;
                } else { // added to make the compiler happy
                    dataToBeSigned = dataToBeSignedLong;
                }

                //======================= BEGINNING OF TESTS WITH MATCHING mdName AND MGF1ParameterSpec    ======================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA1");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA1", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA1, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    assertTrue(result, "signature is invalid!!");

                } catch (Exception ex) {
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Exception thrown with message = " + ex.getMessage());
                    ex.printStackTrace();
                    Assertions.fail();
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA224\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA224");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA224", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA224, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    assertTrue(result, "signature is invalid!!");

                } catch (Exception ex) {
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Exception thrown with message = " + ex.getMessage());
                    ex.printStackTrace();
                    Assertions.fail();
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA256\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA256");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA256", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA256, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    assertTrue(result, "signature is invalid!!");

                } catch (Exception ex) {
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Exception thrown with message = " + ex.getMessage());
                    ex.printStackTrace();
                    Assertions.fail();
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA384\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA384");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA384", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA384, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    // For all key sizes and data lengths
                    if (ii <= 0) { //if key size <= 512
                        fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Instead, this test should have produced an InvalidKeyException");
                    }

                } catch (InvalidKeyException ex) {
                    if (ii <= 0) { //if key size <= 512
                        if (ex.getMessage().indexOf("Key is too short") != -1) {
                            if (printJunitTrace)
                                System.out.println("testRSAPSS(): TEST RESULT #"
                                        + (testCaseNumber - 1)
                                        + " => The expected exception was successfully thrown.");
                        } else {
                            if (printJunitTrace)
                                System.out.println("testRSAPSS(): TEST RESULT #"
                                        + (testCaseNumber - 1)
                                        + " => An unexpected exception was thrown with message = "
                                        + ex.getMessage());
                            Assertions.fail();
                        }
                    } else { // else key size > 512
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA512\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA512");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA512", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA512, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    // For all key sizes and data lengths
                    if (ii <= 0) { //if key size <= 512
                        fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Instead, this test should have produced an InvalidKeyException");
                    }

                } catch (InvalidKeyException ex) {
                    if (ii <= 0) { //if key size <= 512
                        if (ex.getMessage().indexOf("Key is too short") != -1) {
                            if (printJunitTrace)
                                System.out.println("testRSAPSS(): TEST RESULT #"
                                        + (testCaseNumber - 1)
                                        + " => The expected exception was successfully thrown.");
                        } else {
                            if (printJunitTrace)
                                System.out.println("testRSAPSS(): TEST RESULT #"
                                        + (testCaseNumber - 1)
                                        + " => An unexpected exception was thrown with message = "
                                        + ex.getMessage());
                            Assertions.fail();
                        }
                    } else { // else key size > 512
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================
                //======================= END OF TESTS WITH MATCHING mdName AND MGF1ParameterSpec           ======================================
                //======================= BEGINNING OF TESTS WITH MIS-MATCHING mdName AND MGF1ParameterSpec ======================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {

                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA224");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA1", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA224, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => The expected exception was successfully thrown.");
                    } else {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA224\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA256");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA224", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA256, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => The expected exception was successfully thrown.");
                    } else {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {

                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA256\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA384");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA256", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA384, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => The expected exception was successfully thrown.");
                    } else {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {

                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA384\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA512");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA384", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA512, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => The expected exception was successfully thrown.");
                    } else {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA512\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA1");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA512", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA1, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => The expected exception was successfully thrown.");
                    } else {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================
                //======================= END OF TESTS WITH MIS-MATCHING mdName AND MGF1ParameterSpec             ======================================
                //======================= BEGINNING OF TESTS WITH MIS-MATCHING mdName (SHA-1) AND MGF1ParameterSpec ======================================
                // NOTE:  ORACLE DOES NOT SUPPORT mdName = MD5

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA-1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA224");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA-1", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA224, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => The expected exception was successfully thrown.");
                    } else {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA-1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA256");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA-1", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA256, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => The expected exception was successfully thrown.");
                    } else {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA-1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA384");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA-1", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA384, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => The expected exception was successfully thrown.");
                    } else {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA-1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA512");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA-1", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA512, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => The expected exception was successfully thrown.");
                    } else {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA-1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA1");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA-1", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA1, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    assertTrue(true);
                    //fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    fail("Sha1 should not have failed");
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => The expected exception was successfully thrown.");
                    } else {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================
                //======================= END OF TESTS WITH MIS-MATCHING mdName (SHA-1) AND MGF1ParameterSpec ======================================
                //======================= BEGINNING OF TESTS WITH VARIOUS saltLen VALUES                    ======================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA1");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 40");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA1", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA1, // MGFParameterSpec
                            40, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    assertTrue(result, "signature is invalid!!");

                } catch (Exception ex) {
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Exception thrown with message = " + ex.getMessage());
                    ex.printStackTrace();
                    Assertions.fail();
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA224\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA224");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 60");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA224", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA224, // MGFParameterSpec
                            60, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    // For all key sizes and data lengths
                    if (ii <= 0) { //if key size <= 512
                        fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Instead, this test should have produced an InvalidKeyException");
                    }

                } catch (InvalidKeyException ex) {
                    if (ii <= 0) { //if key size <= 512
                        if (ex.getMessage().indexOf("Key is too short") != -1) {
                            if (printJunitTrace)
                                System.out.println("testRSAPSS(): TEST RESULT #"
                                        + (testCaseNumber - 1)
                                        + " => The expected exception was successfully thrown.");
                        } else {
                            if (printJunitTrace)
                                System.out.println("testRSAPSS(): TEST RESULT #"
                                        + (testCaseNumber - 1)
                                        + " => An unexpected exception was thrown with message = "
                                        + ex.getMessage());
                            Assertions.fail();
                        }
                    } else { // else key size > 512
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA256\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA256");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 80");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA256", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA256, // MGFParameterSpec
                            80, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    // For all key sizes and data lengths
                    if (ii <= 0) { //if key size <= 512
                        fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Instead, this test should have produced an InvalidKeyException");
                    }

                } catch (InvalidKeyException ex) {
                    if (ii <= 0) { //if key size <= 512
                        if (ex.getMessage().indexOf("Key is too short") != -1) {
                            if (printJunitTrace)
                                System.out.println("testRSAPSS(): TEST RESULT #"
                                        + (testCaseNumber - 1)
                                        + " => The expected exception was successfully thrown.");
                        } else {
                            if (printJunitTrace)
                                System.out.println("testRSAPSS(): TEST RESULT #"
                                        + (testCaseNumber - 1)
                                        + " => An unexpected exception was thrown with message = "
                                        + ex.getMessage());
                            Assertions.fail();
                        }
                    } else { // else key size > 512
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA384\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA384");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 100");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA384", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA384, // MGFParameterSpec
                            100, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    // For all key sizes and data lengths
                    if (ii <= 1) { //if key size <= 1024
                        fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Instead, this test should have produced an InvalidKeyException");
                    }

                } catch (InvalidKeyException ex) {
                    if (ii <= 1) { //if key size <= 1024
                        if (ex.getMessage().indexOf("Key is too short") != -1) {
                            if (printJunitTrace)
                                System.out.println("testRSAPSS(): TEST RESULT #"
                                        + (testCaseNumber - 1)
                                        + " => The expected exception was successfully thrown.");
                        } else {
                            if (printJunitTrace)
                                System.out.println("testRSAPSS(): TEST RESULT #"
                                        + (testCaseNumber - 1)
                                        + " => An unexpected exception was thrown with message = "
                                        + ex.getMessage());
                            Assertions.fail();
                        }
                    } else { // else key size > 1024
                        if (printJunitTrace) {
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        }
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA512\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA512");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 200");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA512", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA512, // MGFParameterSpec
                            200, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    // For all key sizes and data lengths
                    if (ii <= 2) { //if key size <= 2048
                        fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Instead, this test should have produced an InvalidKeyException");
                    }

                } catch (InvalidKeyException ex) {
                    if (ii <= 2) { //if key size <= 2048
                        if (ex.getMessage().indexOf("Key is too short") != -1) {
                            if (printJunitTrace)
                                System.out.println("testRSAPSS(): TEST RESULT #"
                                        + (testCaseNumber - 1)
                                        + " => The expected exception was successfully thrown.");
                        } else {
                            if (printJunitTrace)
                                System.out.println("testRSAPSS(): TEST RESULT #"
                                        + (testCaseNumber - 1)
                                        + " => An unexpected exception was thrown with message = "
                                        + ex.getMessage());
                            Assertions.fail();
                        }
                    } else { // else key size > 2048
                        if (printJunitTrace) {
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        }
                        Assertions.fail();
                    }
                }

                //======================================================================================================
                //======================= END OF TESTS WITH VARIOUS saltLen VALUES                ======================================
                //======================= BEGINNNING OF TESTS WITH VARIOUS trailerField VALUES    ======================================
                // NOTE:  ORACLE SUPPORTS ONLY A trailerField VALUE OF "1".

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA1");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1"); // 10  NOTE:  ORACLE SUPPORTS ONLY A trailerField VALUE OF "1".

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA1", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA1, // MGFParameterSpec
                            20, // saltLen
                            1); //  // NOTE:  ORACLE SUPPORTS ONLY A trailerField VALUE OF 1 .trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    assertTrue(result, "signature is invalid!!");

                } catch (Exception ex) {
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Exception thrown with message = " + ex.getMessage());
                    ex.printStackTrace();
                    Assertions.fail();
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA224\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA224");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1"); //50");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA224", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA224, // MGFParameterSpec
                            20, // saltLen
                            1); // 50 );                     // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    assertTrue(result, "signature is invalid!!");

                } catch (Exception ex) {
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Exception thrown with message = " + ex.getMessage());
                    ex.printStackTrace();
                    Assertions.fail();
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA256\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA256");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1"); //100");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA256", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA256, // MGFParameterSpec
                            20, // saltLen
                            1); //100 );                    // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    assertTrue(result, "signature is invalid!!");

                } catch (Exception ex) {
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Exception thrown with message = " + ex.getMessage());
                    ex.printStackTrace();
                    Assertions.fail();
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA384\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA384");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1"); // 200");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA384", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA384, // MGFParameterSpec
                            20, // saltLen
                            1); // 200 );                    // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    // For all key sizes and data lengths
                    if (ii <= 0) { //if key size <= 512
                        fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Instead, this test should have produced an InvalidKeyException");
                    }

                } catch (InvalidKeyException ex) {
                    if (ii <= 0) { //if key size <= 512
                        if (ex.getMessage().indexOf("Key is too short") != -1) {
                            if (printJunitTrace)
                                System.out.println("testRSAPSS(): TEST RESULT #"
                                        + (testCaseNumber - 1)
                                        + " => The expected exception was successfully thrown.");
                        } else {
                            if (printJunitTrace)
                                System.out.println("testRSAPSS(): TEST RESULT #"
                                        + (testCaseNumber - 1)
                                        + " => An unexpected exception was thrown with message = "
                                        + ex.getMessage());
                            Assertions.fail();
                        }
                    } else { // else key size > 512
                        if (printJunitTrace) {
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        }
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");
                if (printJunitTrace)
                    System.out.println("================  NEW TEST #" + testCaseNumber
                            + "  =====================================================");
                if (printJunitTrace)
                    System.out.println(
                            "====================================================================================");

                try {
                    if (ii == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    } else if (ii == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 1024");
                    } else if (ii == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 2048");
                    } else if (ii == 3) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    } else if (ii == 4) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 4096");
                    } else if (ii == 5) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 5120");
                    }

                    if (jj == 0) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        if (printJunitTrace)
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
                    if (printJunitTrace)
                        System.out
                                .println("testRSAPSS(): verifyingProviderName                    = "
                                        + verifyingProviderName + "\n");

                    // String mdName  = "SHA1" (default), "SHA224", "SHA256", "SHA384", "SHA512"
                    // String mgfName = "MGF1"
                    // mgfSpec = MGF1ParameterSpec.SHA1 (default)
                    // mgfSpec = MGF1ParameterSpec.SHA224
                    // mgfSpec = MGF1ParameterSpec.SHA256
                    // mgfSpec = MGF1ParameterSpec.SHA384
                    // mgfSpec = MGF1ParameterSpec.SHA512
                    // saltLen = 20     (default)
                    // trailerField = 1 (default)

                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA512\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    if (printJunitTrace)
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA512");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1"); // 1023");Oracle supports only 1

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA512", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA512, // MGFParameterSpec
                            20, // saltLen
                            1); // Oracle supports only 1//1023 );                    trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    if (printJunitTrace)
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    // For all key sizes and data lengths
                    if (ii <= 0) { //if key size <= 512
                        fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Instead, this test should have produced an InvalidKeyException");
                    }

                } catch (InvalidKeyException ex) {
                    if (ii <= 0) { //if key size <= 512
                        if (ex.getMessage().indexOf("Key is too short") != -1) {
                            if (printJunitTrace)
                                System.out.println("testRSAPSS(): TEST RESULT #"
                                        + (testCaseNumber - 1)
                                        + " => The expected exception was successfully thrown.");
                        } else {
                            if (printJunitTrace)
                                System.out.println("testRSAPSS(): TEST RESULT #"
                                        + (testCaseNumber - 1)
                                        + " => An unexpected exception was thrown with message = "
                                        + ex.getMessage());
                            Assertions.fail();
                        }
                    } else { // else key size > 512
                        if (printJunitTrace)
                            System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                    + " => An unexpected exception was thrown with message = "
                                    + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //=======================  END TESTS WITH VARIOUS trailerField VALUES    ======================================
                //======================================================================================================

            } // end loop for each dataToBeSigned length
        } // end loop for each RSA key size
    } // end testRSAPSS()

    // Compute the signature, but do not use PSSParameters class
    private static boolean doSignature(byte[] dataToBeSigned, KeyPair rsaKeyPair,
            String signingProvidersSignatureAlgorithmName,
            String verifingProvidersSignatureAlgorithmName, String signingProviderName,
            String verifyingProviderName,

            PSSParameterSpec pssParameterSpec) throws Exception {
        try {

            testCaseNumber++; // Increment the test case number

            Signature sig = Signature.getInstance(signingProvidersSignatureAlgorithmName,
                    signingProviderName);
            if (pssParameterSpec != null) {
                sig.setParameter(pssParameterSpec);
            } else {
                // Should not happen
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestRSAPSSInterop2.java:  doSignature():  PSSParameterSpec was missing.");
                if (printJunitTrace)
                    System.exit(-1);
            }

            if (rsaKeyPair == null) {
                if (printJunitTrace)
                    System.out.println("doSignature():  rsaKeyPair IS NULL");
                if (printJunitTrace)
                    System.out.println("EXITING");
                if (printJunitTrace)
                    System.exit(-1);
            }
            if (rsaKeyPair.getPrivate() == null) {
                if (printJunitTrace)
                    System.out.println("doSignature():  rsaKeyPair.getPrivate() IS NULL");
                if (printJunitTrace)
                    System.out.println("EXITING");
                if (printJunitTrace)
                    System.exit(-1);
            }

            // Sign the data
            sig.initSign(rsaKeyPair.getPrivate());
            sig.update(dataToBeSigned);
            byte[] sigBytes = sig.sign();

            //=======================================================

            RSAPublicKey translatedPublicKey = null;

            // If signingProviderName == verifyingProviderName, then do not perform key translation.
            if (signingProviderName.equalsIgnoreCase(verifyingProviderName)) {
                if (printJunitTrace) {
                    System.out.println(
                            "BaseTestRSAPSSInterop2.java:  doSignature():  NOT PERFORMING KEY TRANSLATION.  signingProviderName = verifyingProviderName");
                }
                // then no key translation is necessary
                translatedPublicKey = (RSAPublicKey) (rsaKeyPair.getPublic());
            } else { // else translate the RSA public key for the verifying provider
                if (printJunitTrace)
                    System.out.println(
                            "BaseTestRSAPSSInterop2.java:  doSignature():  PERFORMING KEY TRANSLATION.  signingProviderName != verifyingProviderName");
                KeyFactory myKeyFactory = KeyFactory.getInstance("RSA", verifyingProviderName);
                translatedPublicKey = (RSAPublicKey) (myKeyFactory
                        .translateKey(rsaKeyPair.getPublic()));
            }

            if (printJunitTrace)
                System.out.println("doSignature():  The original RSA public key is:");
            if (printJunitTrace)
                System.out.println(rsaKeyPair.getPublic().toString());
            if (printJunitTrace)
                System.out.println("doSignature():  The translated RSA public key is:");
            if (printJunitTrace)
                System.out.println(translatedPublicKey.toString());

            //=======================================================

            sig = Signature.getInstance(verifingProvidersSignatureAlgorithmName,
                    verifyingProviderName);
            if (pssParameterSpec != null) {
                sig.setParameter(pssParameterSpec);
            }

            // Verify the signature
            sig.initVerify(translatedPublicKey);
            sig.update(dataToBeSigned);

            boolean signatureVerified = sig.verify(sigBytes);
            if (printJunitTrace)
                System.out.println(
                        "BaseTestRSAPSSInterop2.java:  doSignature():  Did the signature verify successfully = "
                                + signatureVerified);
            return signatureVerified;
        } catch (Exception ex) {
            //           if (printJunitTrace) System.out.println("BaseTestRSAPSSInterop2.java:  doSignature():  The following exception was thrown: ");
            //           ex.printStackTrace();
            throw ex;
        }
    } // end doSignature( )



    private static void showProviders() {
        java.security.Provider[] providers = Security.getProviders();
        if (printJunitTrace)
            System.out.println("\n================================================");
        if (printJunitTrace)
            System.out.println("The security provider's list is:");
        for (int i = 0; i < providers.length; ++i) {
            if (printJunitTrace)
                System.out.print("provider \"");
            if (printJunitTrace)
                System.out.print(providers[i].getName());
            if (printJunitTrace)
                System.out.print("\": ");
            if (printJunitTrace)
                System.out.println(providers[i].toString());
            //              if (printJunitTrace) System.out.println(providers[i].getInfo());
            if (printJunitTrace)
                System.out.println();
        }

        if (printJunitTrace)
            System.out.println("================================================\n\n\n");
    }



    /** * Converts a byte array to hex string */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
                'E', 'F'};
        int len = block.length;
        int high = 0;
        int low = 0;

        for (int i = 0; i < len; i++) {
            if (i % 16 == 0)
                buf.append('\n');
            high = ((block[i] & 0xf0) >> 4);
            low = (block[i] & 0x0f);
            buf.append(hexChars[high]);
            buf.append(hexChars[low]);
            buf.append(' ');
        }

        return buf.toString();
    }

}

