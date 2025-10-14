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

public class BaseTestMiniRSAPSS2 extends BaseTestJunit5 {

    String signingProvidersSignatureAlgorithmName = null;
    String verifyingProvidersSignatureAlgorithmName = null;
    //SunRsaSign     ==> "RSAPSS"
    //OpenJCEPlus ==> "RSAPSS"
    //SunRsaSign ==> "RSASSA-PSS"

    String signingProviderName = null;
    String verifyingProviderName = null;

    static final byte[] dataToBeSignedShort = "a".getBytes();
    static final byte[] dataToBeSignedMedium = "this is text to test the RSAPSS Signature xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            .getBytes();
    static final byte[] dataToBeSignedLong = "this is text to test the RSAPSS Signature xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            .getBytes();

    KeyPairGenerator rsaKeyPairGen = null;

    KeyPair rsaKeyPair_OpenJCEPlus[] = new KeyPair[1];
    KeyPair rsaKeyPair_SunRsaSign[] = new KeyPair[1];
    KeyPair rsaKeyPair_OpenJCEPlusFIPS[] = new KeyPair[1];

    PSSParameterSpec pssParameterSpec = null;

    int testCaseNumber = 1;

    @BeforeEach
    public void setUp() throws Exception {

        System.out.println(
                "===============================================================================");
        System.out.println(
                "===================== BEGIN TEST CASE BaseTestMiniRSAPSS2 =========================");
        System.out.println(
                "===============================================================================");

        //signingProviderName   = "OpenJCEPlus";
        //verifyingProviderName = "OpenJCEPlus";
        signingProviderName = getProviderName();
        verifyingProviderName = getProviderName();

        java.security.Provider[] providers = Security.getProviders();
        System.out.println("The providers in the providers list are:");
        for (int i = 0; i < providers.length; ++i) {
            System.out.println("Provider #" + i + " = " + providers[i].toString());
            System.out.println();
        }

        if (signingProviderName.equalsIgnoreCase("SunRsaSign")) {
            signingProvidersSignatureAlgorithmName = "RSASSA-PSS";
            verifyingProvidersSignatureAlgorithmName = "RSASSA-PSS";
        } else if (signingProviderName.equalsIgnoreCase("OpenJCEPlus")) {
            signingProvidersSignatureAlgorithmName = "RSAPSS";
            verifyingProvidersSignatureAlgorithmName = "RSAPSS";
        } else if (signingProviderName.equalsIgnoreCase("OpenJCEPlusFIPS")) {
            signingProvidersSignatureAlgorithmName = "RSAPSS";
            verifyingProvidersSignatureAlgorithmName = "RSAPSS";
        }

        System.out.println(
                "BaseTestRSAPSS2.java:  setup():  Following the call to setUp(), signingProviderName   = "
                        + signingProviderName);
        System.out.println(
                "BaseTestRSAPSS2.java:  setup():  Following the call to setUp(), verifyingProviderName = "
                        + verifyingProviderName);


        //================================================================

        if (signingProviderName.equalsIgnoreCase("OpenJCEPlus")) {
            // KeyPairs for OpenJCEPlus
            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "OpenJCEPlus");
            rsaKeyPairGen.initialize(3072, null);
            rsaKeyPair_OpenJCEPlus[0] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_OpenJCEPlus[0] = RSA 3072 
        }

        //================================================================


        if (signingProviderName.equalsIgnoreCase("SunRsaSign")) {
            // KeyPairs for SunRsaSign
            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
            rsaKeyPairGen.initialize(3072, null);
            rsaKeyPair_SunRsaSign[0] = rsaKeyPairGen.generateKeyPair(); // rsaKeyPair_SunRsaSign[2] = RSA 3072

        }

        //================================================================


        if (signingProviderName.equalsIgnoreCase("OpenJCEPlusFIPS")) {
            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "OpenJCEPlusFIPS");
            rsaKeyPairGen.initialize(3072, null);
            rsaKeyPair_OpenJCEPlusFIPS[0] = rsaKeyPairGen.generateKeyPair();
            //rsaKeyPair_OpenJCEPlusFIPS[0] = RSA 3072

        }
    }

    //==================================================================================================================
    //   BEGINNING OF RSA-PSS SIGNATURE TESTS
    //==================================================================================================================

    @Test
    public void testRSAPSS() throws Exception {

        KeyPair rsaKeyPair = null;
        byte[] dataToBeSigned;


        System.out.println(
                "================  BEGINNING OF testRSAPSS()  ================================");

        int ii = 0;
        for (; ii < 1; ii++) { // For each RSA key size
            if (signingProviderName.equalsIgnoreCase("OpenJCEPlus")) {
                if (ii == 0) {
                    rsaKeyPair = rsaKeyPair_OpenJCEPlus[0]; // RSA keylength 3072 
                    System.out.println(
                            "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_OpenJCEPlus[0] ");
                }
            } else if (signingProviderName.equalsIgnoreCase("SunRsaSign")) {
                if (ii == 0) {
                    rsaKeyPair = rsaKeyPair_SunRsaSign[0]; // RSA keylength  3072
                    System.out.println(
                            "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_SunRsaSign[0] ");
                }
            } else if (signingProviderName.equalsIgnoreCase("OpenJCEPlusFIPS")) {
                if (ii == 0) {
                    rsaKeyPair = rsaKeyPair_OpenJCEPlusFIPS[0]; // RSA keylength 3072
                    System.out.println(
                            "TestRSAPSS():  Initializing rsaKeyPair with rsaKeyPair_OpenJCEPlusFIPS[0] ");
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


                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");
                if (!getProviderName().equals("OpenJCEPlusFIPS")) {
                    //FIPS does not support SHA1
                    try {
                        if (ii == 0) {
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                        }

                        if (jj == 0) {
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                        } else if (jj == 1) {
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                        } else if (jj == 2) {
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                        }

                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
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

                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA1\"");
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA1");
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
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


                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                        assertTrue(result, "signature is invalid!!");


                    } catch (Exception ex) {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Exception thrown with message = " + ex.getMessage());
                        ex.printStackTrace();
                        Assertions.fail();
                    }
                }

                //======================================================================================================


                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA224\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA224");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
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

                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                    assertTrue(result, "signature is invalid!!");

                } catch (Exception ex) {
                    System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Exception thrown with message = " + ex.getMessage());
                    ex.printStackTrace();
                    Assertions.fail();
                }

                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }
                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA256\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA256");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
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


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                    assertTrue(result, "signature is invalid!!");

                } catch (Exception ex) {
                    System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Exception thrown with message = " + ex.getMessage());
                    ex.printStackTrace();
                    Assertions.fail();
                }

                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA384\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA384");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
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


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                } catch (InvalidKeyException ex) {
                    System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => An unexpected exception was thrown with message = "
                            + ex.getMessage());
                    Assertions.fail();
                }


                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA512\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA512");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
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


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                    // For all key sizes and data lengths

                } catch (InvalidKeyException ex) {
                    System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => An unexpected exception was thrown with message = "
                            + ex.getMessage());
                    Assertions.fail();
                }


                //======================================================================================================

                //======================= END OF TESTS WITH MATCHING mdName AND MGF1ParameterSpec           ======================================
                //======================= BEGINNING OF TESTS WITH MIS-MATCHING mdName AND MGF1ParameterSpec ======================================


                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mdName           = \"SHA1\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA224");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
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


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => The expected exception was successfully thrown.");
                    } else {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => An unexpected exception was thrown with message = "
                                + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }
                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA224\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA256");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
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


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => The expected exception was successfully thrown.");
                    } else {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => An unexpected exception was thrown with message = "
                                + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA256\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA384");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
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


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => The expected exception was successfully thrown.");
                    } else {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => An unexpected exception was thrown with message = "
                                + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA384\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA512");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
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


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => The expected exception was successfully thrown.");
                    } else {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => An unexpected exception was thrown with message = "
                                + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA512\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA1");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
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


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => The expected exception was successfully thrown.");
                    } else {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => An unexpected exception was thrown with message = "
                                + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================


                //======================= END OF TESTS WITH MIS-MATCHING mdName AND MGF1ParameterSpec             ======================================
                //======================= BEGINNING OF TESTS WITH MIS-MATCHING mdName (MD5) AND MGF1ParameterSpec ======================================


                // NOTE:  ORACLE DOES NOT SUPPORT mdName = MD5


                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println("testRSAPSS(): PSSParameterSpec.mdName           = \"MD5\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA224");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("MD5", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA224, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);



                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => The expected exception was successfully thrown.");
                    } else {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => An unexpected exception was thrown with message = "
                                + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println("testRSAPSS(): PSSParameterSpec.mdName           = \"MD5\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA256");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("MD5", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA256, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);

                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => The expected exception was successfully thrown.");
                    } else {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => An unexpected exception was thrown with message = "
                                + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println("testRSAPSS(): PSSParameterSpec.mdName           = \"MD5\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA384");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("MD5", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA384, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => The expected exception was successfully thrown.");
                    } else {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => An unexpected exception was thrown with message = "
                                + ex.getMessage());
                        Assertions.fail();
                    }
                }


                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println("testRSAPSS(): PSSParameterSpec.mdName           = \"MD5\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA512");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("MD5", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA512, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => The expected exception was successfully thrown.");
                    } else {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => An unexpected exception was thrown with message = "
                                + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println("testRSAPSS(): PSSParameterSpec.mdName           = \"MD5\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA1");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 1");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("MD5", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA1, // MGFParameterSpec
                            20, // saltLen
                            1); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                    fail("       testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Instead, this test should have produced an InvalidAlgorithmParameterException");

                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.") != -1) {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => The expected exception was successfully thrown.");
                    } else {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => An unexpected exception was thrown with message = "
                                + ex.getMessage());
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                //======================= END OF TESTS WITH MIS-MATCHING mdName (MD5) AND MGF1ParameterSpec ======================================
                //======================= BEGINNING OF TESTS WITH VARIOUS saltLen VALUES                    ======================================


                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");
                if (!getProviderName().equals("OpenJCEPlusFIPS")) {
                    //FIPS does not support SHA1 skip test
                    try {
                        if (ii == 0) {
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                        }

                        if (jj == 0) {
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                        } else if (jj == 1) {
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                        } else if (jj == 2) {
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                        }

                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
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

                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA1\"");
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA1");
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 40");
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


                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                        assertTrue(result, "signature is invalid!!");

                    } catch (Exception ex) {
                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " => Exception thrown with message = " + ex.getMessage());
                        ex.printStackTrace();
                        Assertions.fail();
                    }
                }

                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA224\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA224");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 60");
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


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                } catch (InvalidKeyException ex) {
                    System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => An unexpected exception was thrown with message = "
                            + ex.getMessage());
                    Assertions.fail();
                }


                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA256\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA256");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 80");
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


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                } catch (InvalidKeyException ex) {
                    System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => An unexpected exception was thrown with message = "
                            + ex.getMessage());
                    Assertions.fail();
                }


                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA384\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA384");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 100");
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


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);

                } catch (InvalidKeyException ex) {
                    System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => An unexpected exception was thrown with message = "
                            + ex.getMessage());
                    Assertions.fail();
                }

                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA512\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA512");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 200");
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


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);

                } catch (InvalidKeyException ex) {
                    System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => An unexpected exception was thrown with message = "
                            + ex.getMessage());
                    ex.printStackTrace();
                    Assertions.fail();
                }

                //======================================================================================================

                //======================= END OF TESTS WITH VARIOUS saltLen VALUES                ======================================
                //======================= BEGINNNING OF TESTS WITH VARIOUS trailerField VALUES    ======================================


                // NOTE:  ORACLE SUPPORTS ONLY A trailerField VALUE OF "1".


                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mdName           = \"SHA1\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA1");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 10");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA1", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA1, // MGFParameterSpec
                            20, // saltLen
                            10); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                    assertTrue(result, "signature is invalid!!");

                } catch (InvalidAlgorithmParameterException ex) {
                    assertTrue(true);
                } catch (Exception ex) {
                    System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Exception thrown with message = " + ex.getMessage());
                    ex.printStackTrace();
                    Assertions.fail();
                }

                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 3072");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA224\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA224");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 50");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA224", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA224, // MGFParameterSpec
                            20, // saltLen
                            50); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                    assertTrue(result, "signature is invalid!!");

                } catch (InvalidAlgorithmParameterException ex) {
                    assertTrue(true);
                } catch (Exception ex) {
                    System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Exception thrown with message = " + ex.getMessage());
                    ex.printStackTrace();
                    Assertions.fail();
                }

                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA256\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA256");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 100");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA256", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA256, // MGFParameterSpec
                            20, // saltLen
                            100); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);


                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);
                    assertTrue(result, "signature is invalid!!");

                } catch (InvalidAlgorithmParameterException ex) {
                    assertTrue(true);
                } catch (Exception ex) {
                    System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => Exception thrown with message = " + ex.getMessage());
                    ex.printStackTrace();
                    Assertions.fail();
                }

                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                try {
                    if (ii == 0) {
                        System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                    }

                    if (jj == 0) {
                        System.out.println("testRSAPSS():  dataToBeSigned = short");
                    } else if (jj == 1) {
                        System.out.println("testRSAPSS():  dataToBeSigned = medium");
                    } else if (jj == 2) {
                        System.out.println("testRSAPSS():  dataToBeSigned = long");
                    }

                    System.out.println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                            + signingProvidersSignatureAlgorithmName);
                    System.out.println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                            + verifyingProvidersSignatureAlgorithmName);

                    System.out.println("testRSAPSS(): signingProviderName                      = "
                            + signingProviderName);
                    System.out.println("testRSAPSS(): verifyingProviderName                    = "
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

                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA384\"");
                    System.out
                            .println("testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                    System.out.println(
                            "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA384");
                    System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                    System.out.println("testRSAPSS(): PSSParameterSpec.trailerField     = 200");

                    PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA384", // mdName
                            "MGF1", // mgfName
                            MGF1ParameterSpec.SHA384, // MGFParameterSpec
                            20, // saltLen
                            200); // trailerField

                    boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                            signingProvidersSignatureAlgorithmName,
                            verifyingProvidersSignatureAlgorithmName, signingProviderName,
                            verifyingProviderName, pssParameterSpec);



                    System.out.println(
                            "testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1) + " = " + result);

                } catch (InvalidAlgorithmParameterException ex) {
                    assertTrue(true);
                } catch (InvalidKeyException ex) {
                    System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                            + " => An unexpected exception was thrown with message = "
                            + ex.getMessage());
                    Assertions.fail();
                }


                //======================================================================================================

                System.out.println(
                        "====================================================================================");
                System.out.println("================  NEW TEST #" + testCaseNumber
                        + "  =====================================================");
                System.out.println(
                        "====================================================================================");

                if (!getProviderName().equals("OpenJCEPlusFIPS") && ii == 0) {
                    //512 keysize not supported by FIPS
                    try {
                        if (ii == 0) {
                            System.out.println("testRSAPSS():  RSA KEY LENGTH = 512");
                        }

                        if (jj == 0) {
                            System.out.println("testRSAPSS():  dataToBeSigned = short");
                        } else if (jj == 1) {
                            System.out.println("testRSAPSS():  dataToBeSigned = medium");
                        } else if (jj == 2) {
                            System.out.println("testRSAPSS():  dataToBeSigned = long");
                        }

                        System.out
                                .println("testRSAPSS(): signingProvidersSignatureAlgorithmName   = "
                                        + signingProvidersSignatureAlgorithmName);
                        System.out
                                .println("testRSAPSS(): verifyingProvidersSignatureAlgorithmName = "
                                        + verifyingProvidersSignatureAlgorithmName);

                        System.out
                                .println("testRSAPSS(): signingProviderName                      = "
                                        + signingProviderName);
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

                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mdName           = \"SHA512\"");
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.mgfName          = \"MGF1\"");
                        System.out.println(
                                "testRSAPSS(): PSSParameterSpec.MGFParameterSpec = MGF1ParameterSpec.SHA512");
                        System.out.println("testRSAPSS(): PSSParameterSpec.saltLen          = 20");
                        System.out
                                .println("testRSAPSS(): PSSParameterSpec.trailerField     = 1023");

                        PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA512", // mdName
                                "MGF1", // mgfName
                                MGF1ParameterSpec.SHA512, // MGFParameterSpec
                                20, // saltLen
                                1023); // trailerField

                        boolean result = doSignature(dataToBeSigned, rsaKeyPair,
                                signingProvidersSignatureAlgorithmName,
                                verifyingProvidersSignatureAlgorithmName, signingProviderName,
                                verifyingProviderName, pssParameterSpec);



                        System.out.println("testRSAPSS(): TEST RESULT #" + (testCaseNumber - 1)
                                + " = " + result);
                    } catch (InvalidAlgorithmParameterException ex) {
                        assertTrue(true);
                    } catch (InvalidKeyException ex) {
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
    private boolean doSignature(byte[] dataToBeSigned, KeyPair rsaKeyPair,
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
                System.out.println(
                        "BaseTestRSAPSS2.java:  doSignature():  PSSParameterSpec was missing.");
                System.exit(-1);
            }

            if (rsaKeyPair == null) {
                System.out.println("doSignature():  rsaKeyPair IS NULL");
                System.out.println("EXITING");
                System.exit(-1);
            }
            if (rsaKeyPair.getPrivate() == null) {
                System.out.println("doSignature():  rsaKeyPair.getPrivate() IS NULL");
                System.out.println("EXITING");
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
                System.out.println(
                        "BaseTestRSAPSS2.java:  doSignature():  NOT PERFORMING KEY TRANSLATION.  signingProviderName = verifyingProviderName");
                // then no key translation is necessary
                translatedPublicKey = (RSAPublicKey) (rsaKeyPair.getPublic());
            } else { // else translate the RSA public key for the verifying provider
                System.out.println(
                        "BaseTestRSAPSS2.java:  doSignature():  PERFORMING KEY TRANSLATION.  signingProviderName != verifyingProviderName");
                KeyFactory myKeyFactory = KeyFactory.getInstance("RSA", verifyingProviderName);
                translatedPublicKey = (RSAPublicKey) (myKeyFactory
                        .translateKey(rsaKeyPair.getPublic()));
            }

            System.out.println("doSignature():  The original RSA public key is:");
            System.out.println(rsaKeyPair.getPublic().toString());
            System.out.println("doSignature():  The translated RSA public key is:");
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
            System.out.println(
                    "BaseTestRSAPSS2.java:  doSignature():  Did the signature verify successfully = "
                            + signatureVerified);
            return signatureVerified;
        } catch (Exception ex) {
            //            System.out.println("BaseTestRSAPSS2.java:  doSignature():  The following exception was thrown: ");
            //           ex.printStackTrace();
            throw ex;
        }
    } // end doSignature( )



    private void showProviders() {
        java.security.Provider[] providers = Security.getProviders();
        System.out.println("\n================================================");
        System.out.println("The security provider's list is:");
        for (int i = 0; i < providers.length; ++i) {
            System.out.print("provider \"");
            System.out.print(providers[i].getName());
            System.out.print("\": ");
            System.out.println(providers[i].toString());
            //               System.out.println(providers[i].getInfo());
            System.out.println();
        }

        System.out.println("================================================\n\n\n");
    }



    /** * Converts a byte array to hex string */
    private String toHexString(byte[] block) {
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

