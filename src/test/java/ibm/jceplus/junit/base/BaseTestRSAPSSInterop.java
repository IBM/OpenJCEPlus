/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

// A test program to test all DSA classes
package ibm.jceplus.junit.base;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestRSAPSSInterop extends BaseTestJunit5Interop {

    String JCEPlus_ALG = "RSASA-PSS";
    String BC_ALG = "SHA1withRSAandMGF1";
    String SunJCE_ALG = "RSASSA-PSS";
    String BCProvider = "BC";

    static final PSSParameterSpec specSHA1Salt40 = new PSSParameterSpec("SHA1", "MGF1",
            MGF1ParameterSpec.SHA1, 40, 1);
    static final PSSParameterSpec specSHA1Salt32 = new PSSParameterSpec("SHA1", "MGF1",
            MGF1ParameterSpec.SHA1, 32, 1);
    static final PSSParameterSpec specSHA1Salt20 = new PSSParameterSpec("SHA1", "MGF1",
            MGF1ParameterSpec.SHA1, 20, 1);
    static final PSSParameterSpec specSHA256Salt20 = new PSSParameterSpec("SHA256", "MGF1",
            MGF1ParameterSpec.SHA256, 20, 1);
    static final PSSParameterSpec specSHA256Salt32 = new PSSParameterSpec("SHA256", "MGF1",
            MGF1ParameterSpec.SHA256, 32, 1);
    static final String hexSHA256Salt20 = "302fa00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500";
    static final PSSParameterSpec specSHA256Salt40 = new PSSParameterSpec("SHA256", "MGF1",
            MGF1ParameterSpec.SHA256, 40, 1);
    static final String hexSHA256Salt40 = "3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020128";

    String msg = "Hello this is a plain message1\0";
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

    @Test
    public void testRSASignatureWithPSS_SHA1() throws Exception {
        try {
            dotestSignature(content, JCEPlus_ALG, JCEPlus_ALG, 1024, null, getProviderName(),
                    getProviderName());

        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Change the keysize in steps of 32 or 512 to speed up the test case
     * Generate a key once and use it for multiple tests - The OpenJCEPlusFIPS does not allow keysize < 1024
     * @throws Exception
     */
    @Test
    public void testRSAPSSBigMsgMultiKeySize() throws Exception {
        try {
            for (int i = 1024; i < 4096;) {


                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", getProviderName());
                keyGen.initialize(i, new java.security.SecureRandom());
                KeyPair keyPair = keyGen.genKeyPair();

                /* Sign and Verify with JCEPlus only  with PSSParameterSpec.DEFAULT */
                dotestSignature(content3, JCEPlus_ALG, JCEPlus_ALG, keyPair, null, getProviderName(),
                        getProviderName());

                dotestSignature(oneByte, JCEPlus_ALG, JCEPlus_ALG, keyPair, null, getProviderName(),
                        getProviderName());

                dotestSignature(msg.getBytes(), JCEPlus_ALG, JCEPlus_ALG, keyPair, null,
                        getProviderName(), getProviderName());

                dotestSignature(content, JCEPlus_ALG, JCEPlus_ALG, keyPair, null, getProviderName(),
                        getProviderName());



                /* Sign and Verify with 2 providers with PSSParameterSpec.DEFAULT*/

                dotestSignature(content3, JCEPlus_ALG, SunJCE_ALG, keyPair, null, getProviderName(),
                        getInteropProviderName());
                dotestSignature(oneByte, JCEPlus_ALG, SunJCE_ALG, keyPair, null, getProviderName(),
                        getInteropProviderName());
                dotestSignature(msg.getBytes(), JCEPlus_ALG, SunJCE_ALG, keyPair, null,
                        getProviderName(), getInteropProviderName());
                dotestSignature(content, JCEPlus_ALG, SunJCE_ALG, keyPair, null, getProviderName(),
                        getInteropProviderName());


                /* Use Specified salt size - Generarte Signature with JCEPlus and Verify with JCE */
                dotestSignatureProviderAToProviderB(content, JCEPlus_ALG, SunJCE_ALG, keyPair, 20,
                        getProviderName(), getInteropProviderName());
                dotestSignatureProviderAToProviderB(content, JCEPlus_ALG, SunJCE_ALG, keyPair, 30,
                        getProviderName(), getInteropProviderName());
                dotestSignatureProviderAToProviderB(content, JCEPlus_ALG, SunJCE_ALG, keyPair, 40,
                        getProviderName(), getInteropProviderName());

                /* Use Specified salt size - Generarte Signature with JCE and Verify with JCEPlus */

                dotestSignatureProviderAToProviderB(content, SunJCE_ALG, JCEPlus_ALG, keyPair, 20,
                        getInteropProviderName(), getProviderName());
                dotestSignatureProviderAToProviderB(content, SunJCE_ALG, JCEPlus_ALG, keyPair, 30,
                        getInteropProviderName(), getProviderName());
                dotestSignatureProviderAToProviderB(content, SunJCE_ALG, JCEPlus_ALG, keyPair, 40,
                        getInteropProviderName(), getProviderName());


                /* Use Specified salt size - Generarte Signature with JCEPlus and Verify with BC */
                dotestSignatureProviderAToProviderB(content, JCEPlus_ALG, BC_ALG, keyPair, 20,
                        getProviderName(), BCProvider);
                dotestSignatureProviderAToProviderB(content, JCEPlus_ALG, SunJCE_ALG, keyPair, 30,
                        getProviderName(), BCProvider);
                dotestSignatureProviderAToProviderB(content, JCEPlus_ALG, SunJCE_ALG, keyPair, 40,
                        getProviderName(), BCProvider);

                /* Use Specified salt size - Generarte Signature with BC and Verify with JCEPlus */

                dotestSignatureProviderAToProviderB(content, BC_ALG, JCEPlus_ALG, keyPair, 20,
                        BCProvider, getProviderName());
                dotestSignatureProviderAToProviderB(content, BC_ALG, JCEPlus_ALG, keyPair, 30,
                        BCProvider, getProviderName());
                dotestSignatureProviderAToProviderB(content, BC_ALG, JCEPlus_ALG, keyPair, 40,
                        BCProvider, getProviderName());

                i = i + 512;

            }
            assertTrue(true);

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
            for (int i = 1; i <= 10; i++) {
                byte[] dynMsg = new byte[i * 11];
                for (int j = 0; j < i; j++) {
                    System.arraycopy(elevenBytes, 0, dynMsg, j * 11, 11);
                }
                // //System.out.println("msgSize=" + dynMsg.length);
                dotestSignature(dynMsg, JCEPlus_ALG, JCEPlus_ALG, 1024, null, getProviderName(),
                        getProviderName());
                dotestSignature(dynMsg, JCEPlus_ALG, BC_ALG, 1024, null, getProviderName(), BCProvider);
                dotestSignature(dynMsg, BC_ALG, JCEPlus_ALG, 1024, null, BCProvider, getProviderName());

                dotestSignature(dynMsg, JCEPlus_ALG, SunJCE_ALG, 1024, null, getProviderName(),
                        getInteropProviderName());
                dotestSignature(dynMsg, SunJCE_ALG, JCEPlus_ALG, 1024, null, getInteropProviderName(),
                        getProviderName());

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
                //System.out.println("msgSize=" + dynMsg.length);
                doSignatureJCEPlusToOther(dynMsg, JCEPlus_ALG, BC_ALG, 1024, 20, getProviderName(),
                        BCProvider);
                doSignatureJCEPlusToOther(dynMsg, JCEPlus_ALG, BC_ALG, 1024, 40, getProviderName(),
                        BCProvider);
                doSignatureJCEPlusToOther(dynMsg, JCEPlus_ALG, BC_ALG, 1024, -1, getProviderName(),
                        BCProvider);

                //                doSignatureJCEPlusToOther(dynMsg, JCEPlus_ALG, SunJCE_ALG, 1024, 20, providerName, interopProviderName);
                //                doSignatureJCEPlusToOther(dynMsg, JCEPlus_ALG, SunJCE_ALG, 1024, 40, providerName, interopProviderName);
                //                doSignatureJCEPlusToOther(dynMsg, JCEPlus_ALG, SunJCE_ALG, 1024, -1, providerName, interopProviderName);

            }

        } catch (Exception e) {

            e.printStackTrace();
            assertTrue(false);
        }
    }

    //
    //    /** 
    //     * Test after setting parameters
    //     * @throws Exception
    //     */
    //    @org.junit.Test
    //    public void testRSASignatureWithPSSParameterSpec() throws Exception {
    //        try {
    //            dotestSignaturePSSParameterSpec(content1, JCEPlus_ALG, providerName, SunJCE_ALG, interopProviderName,  1024);
    //
    //        } catch (Exception e) {
    //            e.printStackTrace();
    //            assertTrue(false);
    //        }
    //    }
    //
    //    /**
    //     * SHA256
    //     * @throws Exception
    //     */
    //    @org.junit.Test
    //    public void testRSASignatureSHA256() throws Exception {
    //
    //        try {
    //            //specSHA1Salt20 passes for all the cases
    //            PSSParameterSpec pssParameter =  specSHA256Salt32; //specSHA256Salt40;
    //            
    //            dotestSignature(msg.getBytes(), JCEPlus_ALG, JCEPlus_ALG, 2048, pssParameter,
    //                    providerName, providerName);
    //            
    //            dotestSignature(msg.getBytes(), SunJCE_ALG, JCEPlus_ALG, 2048, pssParameter,
    //                    interopProviderName, providerName);
    //            dotestSignature(msg.getBytes(), JCEPlus_ALG, SunJCE_ALG, 2048, pssParameter,
    //                    providerName, interopProviderName);
    //        
    //            
    //
    //        } catch (Exception e) {
    //            
    //            e.printStackTrace();
    //            assertTrue(false);
    //        }
    //    }
    //
    //    /**
    //     * SHA512
    //     * @throws Exception
    //     */
    //    @org.junit.Test
    //    public void testRSASignatureSHA512() throws Exception {
    //
    //        PSSParameterSpec pssParameter = new PSSParameterSpec("SHA512", "MGF1",
    //                MGF1ParameterSpec.SHA512, 64, 1);
    //        try {
    //            dotestSignature(content, JCEPlus_ALG,  SunJCE_ALG, 2048, pssParameter,
    //                    providerName, interopProviderName);
    //        
    //            
    //            dotestSignature(content, SunJCE_ALG,  JCEPlus_ALG, 2048, pssParameter,
    //                    interopProviderName, providerName);
    //            
    //
    //        } catch (Exception e) {
    //            e.printStackTrace();
    //            assertTrue(false);
    //        }
    //    }
    //
    //    /**
    //     * SHA384
    //     * @throws Exception
    //     */
    //    @org.junit.Test
    //    public void testRSASignatureSHA384() throws Exception {
    //        try {
    //            PSSParameterSpec pssParameter = new PSSParameterSpec("SHA384",
    //                    "MGF1", MGF1ParameterSpec.SHA384, 48, 1);
    //            dotestSignature(content, JCEPlus_ALG, SunJCE_ALG, 2048, pssParameter,
    //                    providerName, interopProviderName);
    //            dotestSignature(content, SunJCE_ALG, JCEPlus_ALG, 2048, pssParameter,
    //                    interopProviderName, providerName) ;
    //            
    //            
    //
    //        } catch (Exception e) {
    //            e.printStackTrace();
    //            assertTrue(false);
    //        }
    //    }
    //
    //    /**
    //     * SHA256 - test one byte
    //     */
    //    @org.junit.Test
    //    public void testRSASignatureSHA256OneByte() throws Exception {
    //        try {
    //            PSSParameterSpec pssParameterSpec = specSHA256Salt20;
    //            dotestSignaturePSSParameterSpec(oneByte, JCEPlus_ALG, providerName, SunJCE_ALG, interopProviderName, 2048,
    //                    pssParameterSpec);
    //            dotestSignaturePSSParameterSpec(oneByte, SunJCE_ALG, interopProviderName, JCEPlus_ALG, providerName, 2048,
    //                    pssParameterSpec);
    //
    //
    //        } catch (Exception e) {
    //            e.printStackTrace();
    //            assertTrue(false);
    //        }
    //    }
    //
    //    /**
    //     * OtherToJCEPlus
    //     * @throws Exception
    //     */
    //    @org.junit.Test
    //    public void testRSASignatureSHA1_otherToJCEPlus() throws Exception {
    //        try {
    //            
    //            dotestSignatureKeySizeProviderAToProviderB (oneByte, JCEPlus_ALG, SunJCE_ALG, 2048, -1, providerName, interopProviderName);
    //            dotestSignatureKeySizeProviderAToProviderB (oneByte, JCEPlus_ALG, SunJCE_ALG, 2048, 20, providerName, interopProviderName);
    //            
    //            
    //            
    //            dotestSignatureKeySizeProviderAToProviderB(oneByte, SunJCE_ALG, BC_ALG, 2048, -1, providerName, BCProvider);
    //            dotestSignatureKeySizeProviderAToProviderB(oneByte, SunJCE_ALG, BC_ALG, 2048, 20, providerName, BCProvider);
    //            dotestSignatureKeySizeProviderAToProviderB(oneByte, SunJCE_ALG, BC_ALG, 2048, 40, providerName, BCProvider);
    //            dotestSignatureKeySizeProviderAToProviderB(oneByte, SunJCE_ALG, BC_ALG, 2048, 60, providerName, BCProvider);
    //            dotestSignatureKeySizeProviderAToProviderB(oneByte, BC_ALG, SunJCE_ALG, 2048, 60, BCProvider, providerName);
    //
    //        } catch (Exception e) {
    //            e.printStackTrace();
    //            assertTrue(false);
    //        }
    //    }
    //
    //    /**
    //     * IBM to BC
    //     * @throws Exception
    //     */
    //
    //    @org.junit.Test
    //    public void testRSASignatureSHA1_JCEPlusToOther() throws Exception {
    //        try {
    //            doSignatureJCEPlusToOther(oneByte, JCEPlus_ALG, SunJCE_ALG,1024, -1, providerName, interopProviderName);
    //            doSignatureJCEPlusToOther (oneByte, JCEPlus_ALG, SunJCE_ALG, 1024, -1, providerName, BCProvider);
    //
    //        } catch (Exception e) {
    //            
    //            e.printStackTrace();
    //            assertTrue(false);
    //        }
    //    }
    //
    //    /**
    //     * 0 salt length
    //     * @throws Exception
    //     */
    //    @org.junit.Test
    //    public void testRSASignatureSHA1_IBM2BC_0salt() throws Exception {
    //        try {
    //            doSignatureJCEPlusToOther(oneByte, JCEPlus_ALG, BC_ALG, 1024, 0, providerName, BCProvider );
    //            doSignatureJCEPlusToOther(oneByte, JCEPlus_ALG, SunJCE_ALG, 1024, 0, providerName, interopProviderName );
    //
    //        } catch (Exception e) {
    //            
    //            e.printStackTrace();
    //            assertTrue(false);
    //        }
    //    }
    //    
    /**
     * Helper method
     * @param content
     * @param algorithm
     * @param keySize
     * @param pssParameterSpec
     * @param jceprovider
     * @throws Exception
     */

    protected void dotestSignature(byte[] content, String algorithmA, String algorithmB,
            int keySize, PSSParameterSpec pssParameterSpec, String providerA, String providerB)
            throws Exception {

        // Generate Signature

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", providerA);
        keyGen.initialize(keySize, new java.security.SecureRandom());
        KeyPair keyPair = keyGen.genKeyPair();

        Signature sig = Signature.getInstance(algorithmA, providerA);
        if (pssParameterSpec != null) {
            sig.setParameter(pssParameterSpec);
            AlgorithmParameters algParams = sig.getParameters();
            algParams.getParameterSpec(PSSParameterSpec.class);
            //System.out.println("parameters=" + algParams.toString());
        } else if (providerA.equals("SunRsaSign")) {
            sig.setParameter(new PSSParameterSpec("SHA-1", "MGF1",
                    MGF1ParameterSpec.SHA1, 20, 1));
            AlgorithmParameters algParams = sig.getParameters();
            algParams.getParameterSpec(PSSParameterSpec.class);
        }



        sig.initSign(keyPair.getPrivate());
        sig.update(content);
        byte[] sigBytes = sig.sign();
        //System.out.println("Signature from providerA=" + sigBytes.length + " " +  toHex(sigBytes));



        // Verify the signature
        Signature sig1 = null;
        if (!providerB.equalsIgnoreCase(providerA)) {
            sig1 = Signature.getInstance(algorithmB, providerB);
            if (pssParameterSpec != null) {
                sig1.setParameter(pssParameterSpec);
            } else if (providerB.equalsIgnoreCase("SunRsaSign")) {
                sig1.setParameter(new PSSParameterSpec("SHA-1", "MGF1",
                        MGF1ParameterSpec.SHA1, 20, 1));
                AlgorithmParameters algParams = sig.getParameters();
                algParams.getParameterSpec(PSSParameterSpec.class);
            }
        } else
            sig1 = sig;
        sig1.initVerify(keyPair.getPublic());
        sig1.update(content);

        boolean signatureVerified = sig1.verify(sigBytes);

        assertTrue(signatureVerified, "signature is invalid!!");
    }

    //    
    //    /**
    //     * Helper method
    //     * @param content
    //     * @param algorithm
    //     * @param keyPair
    //     * @param pssParameterSpec
    //     * @throws Exception
    //     */
    //
    protected void dotestSignature(byte[] content, String algorithmA, String algorithmB,
            KeyPair keyPair, PSSParameterSpec pssParameterSpec, String providerA, String providerB)
            throws Exception {

        // Generate Signature

        // KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // keyGen.initialize(keySize, new java.security.SecureRandom());
        // KeyPair keyPair = keyGen.genKeyPair();

        Signature sigA = Signature.getInstance(algorithmA, providerA);
        if (pssParameterSpec != null) {
            sigA.setParameter(pssParameterSpec);
        }
        sigA.initSign(keyPair.getPrivate());
        sigA.update(content);
        byte[] sigBytes = sigA.sign();

        // Verify the signature

        Signature sigB = Signature.getInstance(algorithmB, providerB);
        if (!providerB.equals("SunRSaSign")) {
            if (pssParameterSpec != null) {
                sigB.setParameter(pssParameterSpec);
            } else {
                sigB.setParameter(new PSSParameterSpec("SHA-1", "MGF1",
                        MGF1ParameterSpec.SHA1, 20, 1));
            }

        }
        sigB.initVerify(keyPair.getPublic());
        sigB.update(content);

        // Check Signature
        // Signature verifySig = Signature.getInstance("SHA1withRSA/PSS",
        // JCE_PROVIDER);
        // verifySig.initVerify(cert);
        // verifySig.update(content);
        boolean signatureVerified = sigB.verify(sigBytes);

        assertTrue(signatureVerified, "signature is invalid!!");
    }

    /** 
     * Helper method
     * @param content
     * @param JCEPlusAlgorithm
     * @param OtherProviderAlgorithm
     * @param keySize
     * @param saltSize
     * @throws Exception
     */

    protected void dotestSignatureKeySizeProviderAToProviderB(byte[] content, String algorithmA,
            String algorithmB, int keySize, int saltSize, String providerA, String providerB)
            throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", providerA);
        keyGen.initialize(keySize, new java.security.SecureRandom());
        KeyPair keyPair = keyGen.genKeyPair();

        ProviderAToProviderB(content, algorithmA, algorithmB, keyPair, saltSize, providerA,
                providerB);
    }

    protected void dotestSignatureProviderAToProviderB(byte[] content, String algorithmA,
            String algorithmB, KeyPair keyPair, int saltSize, String providerA, String providerB)
            throws Exception {

        ProviderAToProviderB(content, algorithmA, algorithmB, keyPair, saltSize, providerA,
                providerB);
    }

    /**
     * Helper method to do the BC to IBM
     * @param plaintext
     * @param JCEPlusAlgorithm
     * @param OtherProviderAlgorithm
     * @param keyPair
     * @param saltSize
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    void ProviderAToProviderB(byte[] plaintext, String algorithmA, String algorithmB,
            KeyPair keyPair, int saltSize, String providerA, String providerB)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
            SignatureException {
        // Generate Signature
        PSSParameterSpec pssParameterSpec = null;
        if (saltSize != -1) {
            pssParameterSpec = new PSSParameterSpec("SHA-1", "MGF1",
                    MGF1ParameterSpec.SHA1, saltSize, 1);
        }



        // Signature sig = Signature.getInstance(algorithm, JCE_PROVIDER);
        Signature sig = Signature.getInstance(algorithmA, providerA);
        try {
            if (saltSize != -1)
                sig.setParameter(pssParameterSpec);
        } catch (InvalidAlgorithmParameterException e1) {
            e1.printStackTrace();
        }
        AlgorithmParameters algParams = sig.getParameters();


        try {
            algParams.getParameterSpec(PSSParameterSpec.class);
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
            assertTrue(false);
        }

        sig.initSign(keyPair.getPrivate());
        sig.update(plaintext);
        byte[] sigBytes = sig.sign();
        Signature sigB = null;
        //        System.out.println ("sigBytes(JCE) = " + toHex(sigBytes)); 
        if (!providerA.equals(providerB)) {
            sigB = Signature.getInstance(algorithmB, providerB);
            try {
                if (saltSize != -1)
                    sigB.setParameter(pssParameterSpec);
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
                assertTrue(false);
            }
        } else
            sigB = sig;

        // Verify the signature
        sigB.initVerify(keyPair.getPublic());
        sigB.update(plaintext);

        boolean signatureVerified = sigB.verify(sigBytes);
        /*System.out.println("Inter-op test " + signatureVerified);*/

        assertTrue(signatureVerified, "signature is invalid!!");
    }

    /**
     * Helper to do IBM to BC
     * @param content
     * @param JCEPlusAlgorithm
     * @param OtherProviderAlgorithm
     * @param keySize
     * @param saltsize
     * @throws Exception
     */
    protected void doSignatureJCEPlusToOther(byte[] content, String JCEPlusAlgorithm,
            String OtherProviderAlgorithm, int keySize, int saltsize, String JCEPlusProvider,
            String otherProvider) throws Exception {

        //System.out.println("testSignatureIBM2BC");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", JCEPlusProvider);
        keyGen.initialize(keySize, new java.security.SecureRandom());
        KeyPair keyPair = keyGen.genKeyPair();

        JCEPlusToOther(content, JCEPlusAlgorithm, OtherProviderAlgorithm, keyPair, saltsize,
                JCEPlusProvider, otherProvider);

    }

    /** 
     * helper method
     * 
     * @param content
     * @param JCEPlusAlgorithm
     * @param OtherProviderAlgorithm
     * @param keyPair
     * @param saltsize
     * @throws Exception
     */

    protected void dotestSignatureJCEPlusToOther(byte[] content, String JCEPlusAlgorithm,
            String OtherProviderAlgorithm, KeyPair keyPair, int saltsize, String JCEPlusProvider,
            String otherProvider) throws Exception {

        //System.out.println("testSignatureIBM2BC");

        JCEPlusToOther(content, JCEPlusAlgorithm, OtherProviderAlgorithm, keyPair, saltsize,
                JCEPlusProvider, otherProvider);

    }

    /** 
     * Helper method
     * @param content
     * @param JCEPlusAlgorithm
     * @param OtherProviderAlgorithm
     * @param keyPair
     * @param saltsize
     * @throws Exception
     */
    void JCEPlusToOther(byte[] content, String JCEPlusAlgorithm, String OtherProviderAlgorithm,
            KeyPair keyPair, int saltsize, String JCEPlusProvider, String otherProvider)
            throws Exception {

        PSSParameterSpec pssParameterSpec = null;

        // Generate Signature
        if (saltsize != -1) {
            pssParameterSpec = new PSSParameterSpec("SHA-1", "MGF1",
                    MGF1ParameterSpec.SHA1, saltsize, 1);
        }

        // Signature sig = Signature.getInstance(algorithm, JCE_PROVIDER);
        Signature sig = Signature.getInstance(JCEPlusAlgorithm, JCEPlusProvider);
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
        // //System.out.println("parameters=" + algParams.toString());
        sig.initSign(keyPair.getPrivate());
        sig.update(content);
        byte[] sigBytes = sig.sign();
        Signature sigB = null;
        if (!otherProvider.equals(JCEPlusProvider)) {
            sigB = Signature.getInstance(OtherProviderAlgorithm, otherProvider);
        } else
            sigB = sig;
        if (pssParameterSpec != null) {
            sigB.setParameter(pssParameterSpec);
        }
        // Verify the signature
        sigB.initVerify(keyPair.getPublic());
        sigB.update(content);

        boolean signatureVerified = sigB.verify(sigBytes);
        // //System.out.println("Inter-op test " + signatureVerified);

        assertTrue(signatureVerified);
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
}
