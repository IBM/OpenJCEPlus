/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import ibm.security.internal.spec.CCMParameterSpec;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class BaseTestAESCCMParameters extends BaseTestJunit5 {
    // Valid tagLen values in bits are 32, 48, 64, 80, 96, 112, 128
    public static int tagLenMaximum = 128;
    public static int tagLenMinimum = 32;

    public static int tagLenGood = 128;
    public static int tagLenBad = 79;

    // Valid IV buffer lengths in octets are 7 thru 13 inclusive.
    public static byte[] ivBufferGood = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
            (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a,
            (byte) 0x0b, (byte) 0x0c, (byte) 0x0d};
    public static byte[] ivBufferBad = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
            (byte) 0x05, (byte) 0x06};

    public static int ivBufferOffsetGood = 0;
    public static int ivBufferOffsetBad = 14;

    private static Object myMutexObject = new Object();

    @Test
    public void testAESCCMParameterSpec() {
        synchronized (myMutexObject) {
            System.out.println(
                    "\n======================================================================");
            System.out.println(
                    "BaseTestAESCCMParameters.java:  testAESCCMParameterSpec():  BEGIN TEST");
            System.out.println(
                    "======================================================================\n");
        }

        try {
            new CCMParameterSpec(tagLenMaximum, ivBufferGood);
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameterSpec():  ERROR:  The unexpected exception below was thrown.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        try {
            new CCMParameterSpec(tagLenMinimum, ivBufferGood);
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameterSpec():  ERROR:  The unexpected exception below was thrown.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        try {
            new CCMParameterSpec(tagLenBad, ivBufferGood);
        } catch (IllegalArgumentException iaex) {
            // This exception is expected.
        } catch (Exception iaex) {
            System.out.println(
                    "testAESCCMParameterSpec():  ERROR:  The unexpected exception below was thrown.  ");
            iaex.printStackTrace(System.out);
            Assertions.fail();
        }

        try {
            new CCMParameterSpec(tagLenMaximum, ivBufferBad);
        } catch (IllegalArgumentException iaex) {
            // This exception is expected.
        } catch (Exception iaex) {
            System.out.println(
                    "testAESCCMParameterSpec():  ERROR:  The unexpected exception below was thrown.  ");
            iaex.printStackTrace(System.out);
            Assertions.fail();
        }

        try {
            new CCMParameterSpec(tagLenMaximum, null);
        } catch (IllegalArgumentException iaex) {
            // This exception is expected.
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameterSpec():  ERROR:  The unexpected exception below was thrown.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        //-----------------------------------------------------------------------

        try {

            new CCMParameterSpec(tagLenGood, ivBufferGood,
                    ivBufferOffsetGood, ivBufferGood.length);
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameterSpec():  ERROR:  The unexpected exception below was thrown.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        try {

            new CCMParameterSpec(tagLenBad, ivBufferGood,
                    ivBufferOffsetGood, ivBufferGood.length);
        } catch (IllegalArgumentException iaex) {
            // This exception is expected.
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameterSpec():  ERROR:  The unexpected exception below was thrown.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        try {

            new CCMParameterSpec(tagLenBad, ivBufferGood,
                    ivBufferOffsetGood, ivBufferGood.length);
        } catch (IllegalArgumentException iaex) {
            // This exception is expected.
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameterSpec():  ERROR:  The unexpected exception below was thrown.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        try {

            new CCMParameterSpec(tagLenGood, ivBufferBad,
                    ivBufferOffsetGood, ivBufferGood.length);
        } catch (IllegalArgumentException iaex) {
            // This exception is expected.
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameterSpec():  ERROR:  The unexpected exception below was thrown.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        try {

            new CCMParameterSpec(tagLenGood, ivBufferGood,
                    ivBufferOffsetBad, ivBufferGood.length);
        } catch (IllegalArgumentException iaex) {
            // This exception is expected.
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameterSpec():  ERROR:  The unexpected exception below was thrown.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        try {

            new CCMParameterSpec(tagLenGood, ivBufferGood,
                    ivBufferOffsetGood, ivBufferBad.length);
        } catch (IllegalArgumentException iaex) {
            // This exception is expected.
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameterSpec():  ERROR:  The unexpected exception below was thrown.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        CCMParameterSpec ccmParameterSpec = new CCMParameterSpec(tagLenGood, ivBufferGood,
                ivBufferOffsetGood, ivBufferGood.length);
        if (ccmParameterSpec.getTLen() != tagLenGood) {
            System.out.println("testAESCCMParameterSpec():  ERROR:  An unexpected tagLen value ("
                    + ccmParameterSpec.getTLen()
                    + ") was read from the CCMParameterSpec object.  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }
        byte[] iv = ccmParameterSpec.getIV();
        if (iv.length != ivBufferGood.length) {
            System.out
                    .println("testAESCCMParameterSpec():  ERROR:  An IV with an unexpected length ("
                            + iv.length + ") was read from the CCMParameterSpec object.  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }
        for (int i = 0; i < iv.length; i++) {
            if (iv[i] != ivBufferGood[i]) {
                System.out.println(
                        "testAESCCMParameterSpec():  ERROR:  Unexpected IV bytes were read from the CCMParameterSpec object.  ");
                RuntimeException rtex = new RuntimeException();
                rtex.printStackTrace(System.out);
                Assertions.fail();
            }
        }

        synchronized (myMutexObject) {
            System.out.println(
                    "\n======================================================================");
            System.out.println(
                    "BaseTestAESCCMParameters.java:  testAESCCMParameterSpec():  END TEST");
            System.out.println(
                    "======================================================================\n");
        }

    }


    //==========================================================================================


    @Test
    public void testAESCCMParameters() {
        synchronized (myMutexObject) {
            System.out.println(
                    "\n===================================================================");
            System.out
                    .println("BaseTestAESCCMParameters.java:  testAESCCMParameters():  BEGIN TEST");
            System.out.println(
                    "===================================================================\n");
        }

        CCMParameterSpec ccmParameterSpec1 = null;
        try {
            ccmParameterSpec1 = new CCMParameterSpec(tagLenMaximum, ivBufferGood);
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  The following exception was thrown while instantiating a CCMParameterSpec object.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }


        AlgorithmParameters ccmParameters1 = null;
        try {
            ccmParameters1 = AlgorithmParameters.getInstance("CCM", getProviderName()); // This is an instance of CCMParameters.
            ccmParameters1.init(ccmParameterSpec1);
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  The unexpected exception below was thrown while creating a CCMParameters object.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }


        if (ccmParameters1 == null) {
            System.out.println("testAESCCMParameters():  ERROR:  ccmParameters1 is null.  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }


        if (!(ccmParameters1.getAlgorithm().equals("CCM"))) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  ccmParameters1.getAlgorithm() did not return the string \"CCM\".  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }


        if (!(ccmParameters1.getProvider().getName().equals(getProviderName()))) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  ccmParameters1.getProvider().getname() did not return the string \"OpenJCEPlus\".  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        // Obtain a CCMParameterSpec object from the CCMParameters object
        CCMParameterSpec newCCMParameterSpec = null;
        try {
            newCCMParameterSpec = ccmParameters1
                    .getParameterSpec(CCMParameterSpec.class);
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  The following exception was thrown while encoding and decoding CCMParameters.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        if (ccmParameterSpec1.getTLen() != newCCMParameterSpec.getTLen()) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  CCMParameterSpec with a bad tagLen was produced.  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        if (ccmParameterSpec1.getIV().length != newCCMParameterSpec.getIV().length) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  CCMParameterSpec with a bad IV length was produced.");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        byte[] originalIV = ccmParameterSpec1.getIV();
        byte[] newIV = newCCMParameterSpec.getIV();

        for (int i = 0; i < originalIV.length; i++) {
            if (originalIV[i] != newIV[i]) {
                System.out.println(
                        "testAESCCMParameters():  ERROR:  CCMParameterSpec with a bad IV was produced.  ");
                RuntimeException rtex = new RuntimeException();
                rtex.printStackTrace(System.out);
                Assertions.fail();
            }
        }

        //------------------------------------

        byte[] ccmParameters1Encoded = null;
        String ccmParameters1String = ccmParameters1.toString();
        try {
            ccmParameters1Encoded = ccmParameters1.getEncoded();
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  ccmParameters1.getEncoded() threw the following exception.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }


        AlgorithmParameters ccmParameters2 = null;
        byte[] ccmParameters2Encoded = null;
        try {
            ccmParameters2Encoded = ccmParameters1Encoded;
            ccmParameters2 = AlgorithmParameters.getInstance("CCM", getProviderName()); // This is an instance of CCMParameters.
            ccmParameters2.init(ccmParameters2Encoded);
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  The unexpected exception below was thrown while getting a CCMParameters object.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }


        if (!(ccmParameters2.getAlgorithm().equals("CCM"))) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  ccmParameters2.getAlgorithm() did not return the string \"CCM\".  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        if (!(ccmParameters2.getProvider().getName().equals(getProviderName()))) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  ccmParameters2.getProvider() did not return the string \"OpenJCEPlus\".  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        String ccmParameters2String = ccmParameters2.toString();

        //-----------------------------------------------

        AlgorithmParameters ccmParameters3 = null;
        byte[] ccmParameters3Encoded = null;
        try {
            ccmParameters3Encoded = ccmParameters2Encoded;
            ccmParameters3 = AlgorithmParameters.getInstance("CCM", getProviderName()); // This is an instance of CCMParameters.
            ccmParameters3.init(ccmParameters3Encoded, "decodingMethod");
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  The unexpected exception below was thrown while getting a CCMParameters object.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }


        if (!(ccmParameters3.getAlgorithm().equals("CCM"))) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  ccmParameters3.getAlgorithm() did not return the string \"CCM\".  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        if (!(ccmParameters3.getProvider().getName().equals(getProviderName()))) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  ccmParameters3.getProvider() did not return the string \"OpenJCEPlus\".  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        String ccmParameters3String = ccmParameters3.toString();


        if (!(ccmParameters1String.equals(ccmParameters2String))) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  ccmParameters is not equal to ccmParameters2.  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        if (!(ccmParameters1String.equals(ccmParameters3String))) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  ccmParameters is not equal to ccmParameters3.  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        synchronized (myMutexObject) {
            System.out.println(
                    "\n==================================================================");
            System.out.println("BaseTestAESCCMParameters.java:  testAESCCMParameters():  END TEST");
            System.out.println(
                    "==================================================================\n");
        }
    }


    //==========================================================================================


    @Test
    public void testAESCCMParameterGenerator() {
        synchronized (myMutexObject) {
            System.out.println(
                    "\n==========================================================================");
            System.out.println(
                    "BaseTestAESCCMParameters.java:  testAESCCMParameterGenerator():  BEGIN TEST");
            System.out.println(
                    "==========================================================================\n");
        }

        Provider openJCEPlusProvider = null;
        java.security.Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; ++i) {
            if ((providers[i].getName()).equals(getProviderName())) {
                openJCEPlusProvider = providers[i];
                break;
            }
        }

        if (openJCEPlusProvider == null) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  The OpenJCEPlus provider was not found in the provider's list.  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }


        AlgorithmParameterGenerator ccmParameterGenerator = null;
        try {
            ccmParameterGenerator = AlgorithmParameterGenerator.getInstance("CCM", getProviderName());
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  The unexpected exception below was thrown while getting a CCMParameterGenerator object.  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }


        if (ccmParameterGenerator == null) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  The CCMParameterGenerator is null.  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }


        if (!(ccmParameterGenerator.getAlgorithm().equals("CCM"))) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  CCMParameterGenerator.getAlgorithm() did not return \"CCM\".  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }


        if (!(ccmParameterGenerator.getProvider().getName().equals(getProviderName()))) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  ccmParameterGenerator.getProvider().getName() did not return the string \"OpenJCEPlus\".  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        //-----------------------------------

        // Init CCMParameterGenerator with the CCM tagLen
        SecureRandom secureRandom = new SecureRandom();
        try {
            ccmParameterGenerator.init(128, secureRandom);
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  The unexpected exception below was thrown while executing CCMParameterGenerator.init( tagLen ).  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }


        AlgorithmParameters algorithmParameters = null;
        try {
            algorithmParameters = ccmParameterGenerator.generateParameters();
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  The unexpected exception below was thrown while executing CCMParameterGenerator.generateParameters().  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        if (algorithmParameters == null) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  The generated algorithmParameters are null.  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }


        if (!(algorithmParameters.getClass().getName()
                .equals("java.security.AlgorithmParameters"))) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  algorithmParameters.getClass().getName() did not return the string \"java.security.AlgorithmParameters\".  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }


        if (!(algorithmParameters.getProvider().getName().equals(getProviderName()))) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  algorithmParameters.getProvider().getName() did not return the string \"OpenJCEPlus\".  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }


        if (!(algorithmParameters.getAlgorithm().equals("CCM"))) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  algorithmParameters.getAlgorithm() did not return the string \"CCM\".  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        String algorithmParametersClassName = algorithmParameters.getClass().getName();
        if (algorithmParametersClassName.equals("java.security.AlgorithmParameters") == false) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  The class of the algorithmParameters object below is incorrect.  ");
            System.out.println(algorithmParametersClassName);
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        // Get a CCMParametersSpec object from the generated algorithmParameters (CCMParameters) object
        CCMParameterSpec ccmParameterSpec = null;
        try {
            ccmParameterSpec = algorithmParameters
                    .getParameterSpec(CCMParameterSpec.class);
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  The following exception was thrown while encoding and decoding AlgorithmParameters(CCMParameters).  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        // Verify the tagLen within the CCMParameterSpec object
        if (ccmParameterSpec.getTLen() != 128) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  CCMParameterSpec with a bad tagLen was produced.  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        // Verify the IV within the CCMParameterSpec object
        if ((ccmParameterSpec.getIV().length < 7) || (ccmParameterSpec.getIV().length > 13)) {
            System.out.println(
                    "testAESCCMParameters():  ERROR:  CCMParameterSpec with a bad IV length was produced.  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        byte[] iv = ccmParameterSpec.getIV();
        System.out.println("testAESCCMParameters():  The IV below should contain random bytes:");
        System.out.println(toHexString(iv));

        // ----------------------------------------------------------------------

        //Init theCCMParameterGenerator with a CCMParameterSpec object
        // Reminder:   int tagLenMaximum = 128;
        // Reminider:  byte[] ivBufferBad  = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06 };
        ccmParameterSpec = new CCMParameterSpec(tagLenMaximum, ivBufferGood);
        secureRandom = new SecureRandom();
        try {
            ccmParameterGenerator.init(ccmParameterSpec, secureRandom);
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  The unexpected exception below was thrown while executing CCMParameterGenerator.init(int size).  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        algorithmParameters = null;
        try {
            algorithmParameters = ccmParameterGenerator.generateParameters();
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  The unexpected exception below was thrown while executing CCMParameterGenerator.generateParameters().  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        if (algorithmParameters == null) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  The generated algorithmParameters are null.  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        if (!(algorithmParameters.getClass().getName()
                .equals("java.security.AlgorithmParameters"))) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  algorithmParameters.getClass().getName() did not return the string \"java.security.AlgorithmParameters\".  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        if (!(algorithmParameters.getProvider().getName().equals(getProviderName()))) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  algorithmParameters.getProvider().getName() did not return the string \"OpenJCEPlus\".  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        if (!(algorithmParameters.getAlgorithm().equals("CCM"))) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  algorithmParameters.getAlgorithm() did not return the string \"CCM\".  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        algorithmParametersClassName = algorithmParameters.getClass().getName();
        if (algorithmParametersClassName.equals("java.security.AlgorithmParameters") == false) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  The class of the algorithmParameters object below is incorrect.  ");
            System.out.println(algorithmParametersClassName);
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        // Get a CCMParametersSpec object from the generated algorithmParameters (CCMParameters) object
        ccmParameterSpec = null;
        try {
            ccmParameterSpec = algorithmParameters
                    .getParameterSpec(CCMParameterSpec.class);
        } catch (Exception ex) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  The following exception was thrown while encoding and decoding AlgorithmParameters(CCMParameters).  ");
            ex.printStackTrace(System.out);
            Assertions.fail();
        }

        // Verify the tagLen within the CCMParameterSpec object
        if (ccmParameterSpec.getTLen() != 128) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  CCMParameterSpec with a bad tagLen was produced.  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        // Verify the IV within the CCMParameterSpec object
        if ((ccmParameterSpec.getIV().length < 7) || (ccmParameterSpec.getIV().length > 13)) {
            System.out.println(
                    "testAESCCMParameterGenerator():  ERROR:  CCMParameterSpec with a bad IV length was produced.  ");
            RuntimeException rtex = new RuntimeException();
            rtex.printStackTrace(System.out);
            Assertions.fail();
        }

        iv = ccmParameterSpec.getIV();

        // Check to ensure the iv contains the bytes x00, x01, x02, x03, x04, x05, x06, x07.
        for (int i = 0; i < iv.length; i++) {
            if (iv[i] != i + 1) {
                System.out.println(
                        "testAESCCMParameterGenerator():  ERROR:  The IV does not contain the bytes x00, x01, x02, x03, x04, x05, x06, x07.");
                System.out.println("testAESCCMParameterGenerator():  The IV bytes are:");
                for (int j = 0; j < iv.length; j++) {
                    System.out.println("iv[" + j + "] = " + iv[j]);
                }
                RuntimeException rtex = new RuntimeException();
                rtex.printStackTrace(System.out);
                Assertions.fail();
            }
        }

        synchronized (myMutexObject) {
            System.out.println(
                    "\n==========================================================================");
            System.out.println(
                    "BaseTestAESCCMParameters.java:  testAESCCMParameterGenerator():  END TEST");
            System.out.println(
                    "==========================================================================\n");
        }
    }


    //==========================================================================================


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
        buf.append('\n');

        return buf.toString();
    }

}
