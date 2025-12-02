/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class BaseTestPQCSignatureWithAliases extends BaseTestJunit5Signature {

    boolean doSignatureTest = false;   // If false, generate key pairs only.  Do not execute the signature portion of the test case.

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_512", "MLKEM512", "OID.2.16.840.1.101.3.4.4.1", "2.16.840.1.101.3.4.4.1",
        "ML-KEM-768", "ML_KEM_768", "MLKEM768", "OID.2.16.840.1.101.3.4.4.2", "2.16.840.1.101.3.4.4.2",
        "ML-KEM-1024", "ML_KEM_1024", "MLKEM1024", "OID.2.16.840.1.101.3.4.4.3", "2.16.840.1.101.3.4.4.3",
        "ML-DSA", "ML-DSA-44", "ML_DSA_44", "MLDSA44", "OID.2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.3.17",
        "ML-DSA-65", "ML_DSA_65", "MLDSA65", "OID.2.16.840.1.101.3.4.3.18", "2.16.840.1.101.3.4.3.18",
        "ML-DSA-87", "ML_DSA_87", "MLDSA87", "OID.2.16.840.1.101.3.4.3.19", "2.16.840.1.101.3.4.3.19"})
    public void testPQCKeys(String pqcKeyType) {

        int numberOfTestsExecuted = 0;
        int testSuccesses         = 0;
        int testFailures          = 0;

        byte[] messageToBeSigned = null;
        byte[] shortMessageToBeSigned   = "Short msg".getBytes();
        byte[] mediumMessageToBeSigned  = "Medium msg 0123456789012345678901234567890123456789012345678901234567890123456789".getBytes();
        byte[] longMessageToBeSigned    = "Long msg 01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789".getBytes();

        for (int i=0; i<10; i++) { // Execute 10 times

            // THIS TEST CASE WILL EXECUTE 3 TIMES.  ONCE FOR EACH MESSAGE SIZE.
            for (int whichMessageToSign=0; whichMessageToSign<=2; whichMessageToSign++) {

                if ( whichMessageToSign == 0 ) {
                    messageToBeSigned = shortMessageToBeSigned;
                } else if ( whichMessageToSign  == 1 ) {
                    messageToBeSigned = mediumMessageToBeSigned;
                } else if ( whichMessageToSign  == 2 ) {
                    messageToBeSigned = longMessageToBeSigned;
                }

                /*System.out.println("\n==============================================================================");
                if (whichMessageToSign == 0) {
                    System.out.println("Testing key type = " + pqcKeyType + "  and  message = short"  );
                } else if (whichMessageToSign == 1) {
                    System.out.println("Testing key type = " + pqcKeyType + "  and  message = medium" );
                } else if (whichMessageToSign == 2) {
                    System.out.println("Testing key type = " + pqcKeyType + "  and  message = long"   );
                } else {
                    System.out.println("Test case error.  ExITING.");
                    System.exit(-1);
                }
                System.out.println("==============================================================================\n"); */

                try {
                    testPQCSignature(pqcKeyType, messageToBeSigned);
                    testSuccesses++;
                } catch (Exception ex) {
                    System.out.println("\nTHE FOLLOWING EXCEPTION WAS THROWN FOR PQC KEY TYPE = " + pqcKeyType);
                    //ex.printStackTrace(System.out);
                    testFailures++;
                }
                numberOfTestsExecuted++;

                //System.out.println("\n============================================================================");
                //System.out.println("============================================================================");
                //System.out.println("============================================================================");
                //System.out.println("============================================================================\n");

            }

        }  // end for 10 repetitions

        System.out.println("\n=========== TEST RESULTS SUMMARY =============");
        System.out.println("\nNumber of tests executed    = " + numberOfTestsExecuted );
        System.out.println("Number of successes         = " + testSuccesses );
        System.out.println("Number of failures          = " + testFailures );
    }



    public void testPQCSignature(String Algorithm, byte[] dataToBeSigned) throws Exception {

        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support plain keys
            System.out.println("FIPS does not support plain keys.  Returning to caller.");
            return;
        }

        //System.out.println("generateKeyPair( ):   The provider name is:  " + getProviderName( ) );
        //System.out.println("testPQCSignature( ):  Calling generateKeyPair( " + Algorithm + " ) ");
        KeyPair keyPair = generateKeyPair(Algorithm);
        //System.out.println("testPQCSignature( ):  Returned from generateKeyPair( " + Algorithm + " ) ");
        if (keyPair == null) {
            System.out.println("generateKeyPair( ):   The provider name is:  " + getProviderName( ) );
            System.out.println("testPQCSignature( ):  Returned from generateKeyPair( " + Algorithm + " ) ");
            System.out.println("testPQCSignature( ):  The returned keyPair is NULL");
        }

        PublicKey publicKey   = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        //System.out.println("\ntestPQCSignature():   The publicKey is:   " + publicKey.toString() );
        //System.out.println("\ntestPQCSignature():   The privateKey is:  " + privateKey.toString() );    // This probably won't work.

        if (!(Algorithm.contains("KEM")|| Algorithm.contains("2.16.840.1.101.3.4.4"))) {
            //System.out.println("testPQCSignature( ):  Calling doSignVerify( )");
            doSignVerify(Algorithm, dataToBeSigned, privateKey, publicKey);    // Do Sign/Verify
            //System.out.println("testPQCSignature( ):  Returned from doSignVerify( )");
        }
    }

    protected KeyPair generateKeyPair(String Algorithm) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(Algorithm, getProviderName() );
        return keyPairGen.generateKeyPair();
    }

    protected void doSignVerify(String sigAlgo, byte[] message, PrivateKey privateKey,
                                PublicKey publicKey) throws Exception {

        Signature signature = Signature.getInstance(sigAlgo, getProviderName());

        // Compute signature
        signature.initSign(privateKey);
        signature.update(message);
        byte[] signedBytes = signature.sign();

        // Verify signature
        signature.initVerify(publicKey);
        signature.update(message);
        if ( signature.verify(signedBytes) == false ) {
            System.out.println("doSignVerify():       Signature verification FAILURE = "+sigAlgo);
        } else {
            // System.out.println("doSignVerify():       Signature verification SUCCESSFUL");
            return;
        }
    }

}

