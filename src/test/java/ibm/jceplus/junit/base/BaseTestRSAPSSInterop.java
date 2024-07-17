/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BaseTestRSAPSSInterop extends BaseTestInterop {

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


    public BaseTestRSAPSSInterop(String providerName, String interopProviderName) {
        super(providerName, interopProviderName);
        Security.addProvider(new BouncyCastleProvider());
    }

    protected void setUp() throws Exception {

    }

    @org.junit.Test
    public void testRSASignatureWithPSS_SHA1() throws Exception {
        try {
            dotestSignature(content, JCEPlus_ALG, JCEPlus_ALG, 1024, null, providerName,
                    providerName);

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
    @org.junit.Test
    public void testRSAPSSBigMsgMultiKeySize() throws Exception {
        try {
            for (int i = 1024; i < 4096;) {


                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", providerName);
                keyGen.initialize(i, new java.security.SecureRandom());
                KeyPair keyPair = keyGen.genKeyPair();

                /* Sign and Verify with JCEPlus only  with PSSParameterSpec.DEFAULT */
                dotestSignature(content3, JCEPlus_ALG, JCEPlus_ALG, keyPair, null, providerName,
                        providerName);

                dotestSignature(oneByte, JCEPlus_ALG, JCEPlus_ALG, keyPair, null, providerName,
                        providerName);

                dotestSignature(msg.getBytes(), JCEPlus_ALG, JCEPlus_ALG, keyPair, null,
                        providerName, providerName);

                dotestSignature(content, JCEPlus_ALG, JCEPlus_ALG, keyPair, null, providerName,
                        providerName);



                /* Sign and Verify with 2 providers with PSSParameterSpec.DEFAULT*/

                dotestSignature(content3, JCEPlus_ALG, SunJCE_ALG, keyPair, null, providerName,
                        interopProviderName);
                dotestSignature(oneByte, JCEPlus_ALG, SunJCE_ALG, keyPair, null, providerName,
                        interopProviderName);
                dotestSignature(msg.getBytes(), JCEPlus_ALG, SunJCE_ALG, keyPair, null,
                        providerName, interopProviderName);
                dotestSignature(content, JCEPlus_ALG, SunJCE_ALG, keyPair, null, providerName,
                        interopProviderName);


                /* Use Specified salt size - Generarte Signature with JCEPlus and Verify with JCE */
                dotestSignatureProviderAToProviderB(content, JCEPlus_ALG, SunJCE_ALG, keyPair, 20,
                        providerName, interopProviderName);
                dotestSignatureProviderAToProviderB(content, JCEPlus_ALG, SunJCE_ALG, keyPair, 30,
                        providerName, interopProviderName);
                dotestSignatureProviderAToProviderB(content, JCEPlus_ALG, SunJCE_ALG, keyPair, 40,
                        providerName, interopProviderName);

                /* Use Specified salt size - Generarte Signature with JCE and Verify with JCEPlus */

                dotestSignatureProviderAToProviderB(content, SunJCE_ALG, JCEPlus_ALG, keyPair, 20,
                        interopProviderName, providerName);
                dotestSignatureProviderAToProviderB(content, SunJCE_ALG, JCEPlus_ALG, keyPair, 30,
                        interopProviderName, providerName);
                dotestSignatureProviderAToProviderB(content, SunJCE_ALG, JCEPlus_ALG, keyPair, 40,
                        interopProviderName, providerName);


                /* Use Specified salt size - Generarte Signature with JCEPlus and Verify with BC */
                dotestSignatureProviderAToProviderB(content, JCEPlus_ALG, BC_ALG, keyPair, 20,
                        providerName, BCProvider);
                dotestSignatureProviderAToProviderB(content, JCEPlus_ALG, SunJCE_ALG, keyPair, 30,
                        providerName, BCProvider);
                dotestSignatureProviderAToProviderB(content, JCEPlus_ALG, SunJCE_ALG, keyPair, 40,
                        providerName, BCProvider);

                /* Use Specified salt size - Generarte Signature with BC and Verify with JCEPlus */

                dotestSignatureProviderAToProviderB(content, BC_ALG, JCEPlus_ALG, keyPair, 20,
                        BCProvider, providerName);
                dotestSignatureProviderAToProviderB(content, BC_ALG, JCEPlus_ALG, keyPair, 30,
                        BCProvider, providerName);
                dotestSignatureProviderAToProviderB(content, BC_ALG, JCEPlus_ALG, keyPair, 40,
                        BCProvider, providerName);

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
    @org.junit.Test
    public void testRSASignatureWithPSSMultiByteSize_timed() throws Exception {
        try {
            for (int i = 1; i <= 10; i++) {
                byte[] dynMsg = new byte[i * 11];
                for (int j = 0; j < i; j++) {
                    System.arraycopy(elevenBytes, 0, dynMsg, j * 11, 11);
                }
                // //System.out.println("msgSize=" + dynMsg.length);
                dotestSignature(dynMsg, JCEPlus_ALG, JCEPlus_ALG, 1024, null, providerName,
                        providerName);
                dotestSignature(dynMsg, JCEPlus_ALG, BC_ALG, 1024, null, providerName, BCProvider);
                dotestSignature(dynMsg, BC_ALG, JCEPlus_ALG, 1024, null, BCProvider, providerName);

                dotestSignature(dynMsg, JCEPlus_ALG, SunJCE_ALG, 1024, null, providerName,
                        interopProviderName);
                dotestSignature(dynMsg, SunJCE_ALG, JCEPlus_ALG, 1024, null, interopProviderName,
                        providerName);

            }

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            assertTrue(false);
        }
    }
    //
    //
    //    

    /** Test multiple raw messages generated by IBM and verified by BC
     * 
     * @throws Exception
     */

    @org.junit.Test
    public void testRSASignatureWithPSSMultiByteSize_IBM2BC2() throws Exception {
        try {
            for (int i = 1; i <= 301; i++) {
                byte[] dynMsg = new byte[i * 11];
                for (int j = 0; j < i; j++) {
                    System.arraycopy(elevenBytes, 0, dynMsg, j * 11, 11);
                }
                //System.out.println("msgSize=" + dynMsg.length);
                doSignatureJCEPlusToOther(dynMsg, JCEPlus_ALG, BC_ALG, 1024, 20, providerName,
                        BCProvider);
                doSignatureJCEPlusToOther(dynMsg, JCEPlus_ALG, BC_ALG, 1024, 40, providerName,
                        BCProvider);
                doSignatureJCEPlusToOther(dynMsg, JCEPlus_ALG, BC_ALG, 1024, -1, providerName,
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
    //            // TODO Auto-generated catch block
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
    //            // TODO Auto-generated catch block
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
    //            // TODO Auto-generated catch block
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
    //            // TODO Auto-generated catch block
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
    //            // TODO Auto-generated catch block
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

        assertTrue("signature is invalid!!", signatureVerified);
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

        assertTrue("signature is invalid!!", signatureVerified);
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
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        AlgorithmParameters algParams = sig.getParameters();


        try {
            algParams.getParameterSpec(PSSParameterSpec.class);
        } catch (InvalidParameterSpecException e) {
            // TODO Auto-generated catch block
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
                // TODO Auto-generated catch block
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

        assertTrue("signature is invalid!!", signatureVerified);
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
            // TODO Auto-generated catch block
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

    /** 
    //     * Helper method
    //     * @param content
    //     * @param algorithm
    //     * @param keySize
    //     * @throws Exception
    //     */
    //
    //    protected void dotestSignaturePSSParameterSpec(byte[] content,
    //            String algorithmA, String providerA, String algorithmB, String providerB, int keySize) throws Exception {
    //        //System.out.println("testSignaturePSSParameterSpec");
    //
    //        // Generate Signature
    //
    //        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", providerA);
    //        keyGen.initialize(keySize, new java.security.SecureRandom());
    //        KeyPair keyPair = keyGen.genKeyPair();
    //
    //        Signature sig = Signature.getInstance(algorithmA, providerA);
    //        // Set salt length
    //        PSSParameterSpec pss = new PSSParameterSpec(20);
    //        sig.setParameter(pss);
    //        sig.initSign(keyPair.getPrivate());
    //        sig.update(content);
    //        byte[] sigBytes = sig.sign();
    //
    //        // Verify the signature
    //        Signature sigB = Signature.getInstance(algorithmB, providerB);
    //        sigB.setParameter(pss);
    //        sigB.initVerify(keyPair.getPublic());
    //        sigB.update(content);
    //
    //        boolean signatureVerified = sigB.verify(sigBytes);
    //
    //        assertTrue("signature is invalid!!", signatureVerified);
    //    }
    //
    //    /**
    //     * Helper method
    //     * @param content
    //     * @param algorithm
    //     * @param keySize
    //     * @param pssParameterSpec
    //     * @throws Exception
    //     */
    //    protected void dotestSignaturePSSParameterSpec(byte[] content,
    //            String algorithmA, String providerA, String algorithmB, String providerB, int keySize, PSSParameterSpec pssParameterSpec)
    //            throws Exception {
    //        //System.out.println("testSignaturePSSParameterSpec algorithm= "
    //        //        + algorithm + " keysize=" + keySize);
    //
    //        // Generate Signature
    //
    //        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", providerA);
    //        keyGen.initialize(keySize, new java.security.SecureRandom());
    //        KeyPair keyPair = keyGen.genKeyPair();
    //
    //        Signature sig = Signature.getInstance(algorithmA, providerA);
    //        // Set salt length
    //        if (pssParameterSpec != null) {
    //            sig.setParameter(pssParameterSpec);
    //        }
    //        sig.initSign(keyPair.getPrivate());
    //        sig.update(content);
    //        byte[] sigBytes = sig.sign();
    //
    //        Signature sigB = Signature.getInstance(algorithmB, providerB);
    //        if (pssParameterSpec != null) {
    //            sigB.setParameter(pssParameterSpec);
    //        }
    //        // Verify the signature
    //        sigB.initVerify(keyPair.getPublic());
    //        sigB.update(content);
    //
    //        boolean signatureVerified = sigB.verify(sigBytes);
    //
    //        assertTrue("signature is invalid!!", signatureVerified);
    //    }
    //////
    //    /**
    //     * Empty parameters
    //     * @throws Exception
    //     */
    //    @org.junit.Test
    //    public void testCertSelfSignVerifyEmptyParams() throws Exception {
    //
    //        String alias = "TestRSAPSS";
    //        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
    //        String keyAlgName = "RSA";
    //        int keysize = 1024;
    //        String sigAlgName = "RSAPSS";
    //
    //        try {
    //        doGenKeyPair(alias, dname, keyAlgName, keysize, sigAlgName,
    //                EMPTY_PARAMS, providerName);
    //        doGenKeyPair(alias, dname, keyAlgName, keysize, sigAlgName,
    //                EMPTY_PARAMS, interopProviderName);
    //        } catch (Exception ex) {
    //            ex.printStackTrace();
    //            assertTrue(false);
    //        }
    //        
    //
    //    }
    //
    //    /**
    //     * IBM to BC empty params
    //     * @throws Exception
    //     */
    //    @org.junit.Test
    //    public void testCertIBM2BCEmptyParams() throws Exception {
    //
    //        String alias = "TestRSAPSS";
    //        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
    //        String keyAlgName = "RSA";
    //        int keysize = 1024;
    //        String sigAlgName = "RSAPSS";
    //
    //        doGenKeyPair(alias, dname, keyAlgName, keysize, sigAlgName,
    //                EMPTY_PARAMS, interopProviderName);
    //
    //    }
    //
    //    
    //
    //    @org.junit.Test
    //    public void testCertIBM2BCParamsSalt40() throws Exception {
    //
    //        String alias = "TestRSAPSS";
    //        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
    //        String keyAlgName = "RSA";
    //        int keysize = 1024;
    //        String sigAlgName = "RSAPSS";
    //
    //        doGenKeyPairBC (alias, dname, keyAlgName, keysize, sigAlgName,
    //                PARAMS_SALT40, interopProviderName);
    //
    //    }
    //
    //    /**
    //     * BC to IBM all default parameters
    //     * @throws Exception
    //     */
    //    @org.junit.Test
    //    public void testCertJCEPlus2OtherDefaultParams() throws Exception {
    //
    //        String alias = "TestRSAPSS";
    //        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
    //        String keyAlgName = "RSA";
    //        int keysize = 1024;
    //        String sigAlgName = "RSAPSS";
    //
    //        doGenKeyPairBC(alias, dname, keyAlgName, keysize, sigAlgName,
    //                DEFAULT_PARAMS, providerName);
    //
    //    }
    //
    //    /**
    //     * Default parameters
    //     * @throws Exception
    //     */
    //    @org.junit.Test
    //    public void testCertSelfSignVerifyDefaultParams() throws Exception {
    //
    //        String alias = "TestRSAPSS";
    //        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
    //        String keyAlgName = "RSA";
    //        int keysize = 1024;
    //        String sigAlgName = "RSAPSS";
    //
    //        doGenKeyPair(alias, dname, keyAlgName, 1024, sigAlgName, DEFAULT_PARAMS, providerName);
    //        doGenKeyPair(alias, dname, keyAlgName, 1024, sigAlgName, DEFAULT_PARAMS, providerName);
    //        doGenKeyPair(alias, dname, keyAlgName, 2048, sigAlgName, DEFAULT_PARAMS, providerName);
    //        doGenKeyPair(alias, dname, keyAlgName, 1024, sigAlgName, DEFAULT_PARAMS, interopProviderName);
    //        doGenKeyPair(alias, dname, keyAlgName, 1024, sigAlgName, DEFAULT_PARAMS, interopProviderName);
    //        doGenKeyPair(alias, dname, keyAlgName, 2048, sigAlgName, DEFAULT_PARAMS, interopProviderName);
    //
    //    }
    //    
    //    /**
    //     * Non default parameters
    //     * @throws Exception
    //     */
    //
    //    @org.junit.Test
    //    public void testCertSelfSignVerifyNonDefaultParams() throws Exception {
    //
    //        String alias = "TestRSAPSS";
    //        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
    //        String keyAlgName = "RSA";
    //        int keysize = 1024;
    //        String sigAlgName = "RSAPSS";
    //
    //        doGenKeyPair(alias, dname, keyAlgName, 1024, sigAlgName,
    //                NONDEFAULT_PARAMS, providerName);
    //        doGenKeyPair(alias, dname, keyAlgName, 1024, sigAlgName, NONDEFAULT_PARAMS, providerName);
    //        doGenKeyPair(alias, dname, keyAlgName, 2048, sigAlgName, NONDEFAULT_PARAMS, providerName);
    //
    //    }
    //
    //    /**
    //     * Non RSAPSS cert to make sure other certs are not broken by RSA-PSS
    //     */
    //    @org.junit.Test
    //    public void testCertNonPSS() throws Exception {
    //
    //        String alias = "TestNonRSAPSS";
    //        String dname = "CN=TestNonRSAPSS,OU=Tivoli,O=IBM,C=US";
    //        String keyAlgName = "RSA";
    //        int keysize = 1024;
    //        
    //
    //        doGenKeyPair(alias, dname, keyAlgName, keysize, "SHA1WithRSA",
    //                EMPTY_PARAMS, providerName);
    //        doGenKeyPair(alias, dname, keyAlgName, keysize, "SHA2WithRSA",
    //                EMPTY_PARAMS, providerName);
    //    }
    //
    //    /**
    //     * only the Salt is non default
    //     * @throws Exception
    //     */
    //    @org.junit.Test
    //    public void testCertSelfSignDefaultParamsExceptSalt() throws Exception {
    //
    //        String alias = "TestRSAPSS";
    //        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
    //        String keyAlgName = "RSA";
    //        int keysize = 1024;
    //        String sigAlgName = "RSAPSS";
    //
    //        doGenKeyPair(alias, dname, keyAlgName, 1024, sigAlgName, PARAMS_SALT40, providerName);
    //        doGenKeyPair(alias, dname, keyAlgName, 1024, sigAlgName, PARAMS_SALT40, providerName);
    //        doGenKeyPair(alias, dname, keyAlgName, 2048, sigAlgName, PARAMS_SALT40, providerName);
    //
    //    }
    //
    //    /**
    //     * IBM to BC
    //     * @throws Exception
    //     */
    //    @org.junit.Test
    //    public void testCertSelfSignDefaultParamsExceptSaltBC() throws Exception {
    //
    //        String alias = "TestRSAPSS";
    //        String dname = "CN=TestRSAPSS,OU=Tivoli,O=IBM,C=US";
    //        String keyAlgName = "RSA";
    //        int keysize = 1024;
    //        String sigAlgName = "RSAPSS";
    //
    //        doGenKeyPairBC (alias, dname, keyAlgName, 512, sigAlgName, PARAMS_SALT40, providerName);
    //        doGenKeyPairBC (alias, dname, keyAlgName, 1024, sigAlgName,
    //                PARAMS_SALT40,providerName);
    //        doGenKeyPairBC (alias, dname, keyAlgName, 2048, sigAlgName,
    //                PARAMS_SALT40, providerName);
    //
    //    }
    //
    //    /**
    //     * Creates a new key pair and self-signed certificate.
    //     */
    //    private void doGenKeyPair(String alias, String dname, String keyAlgName,
    //            int keysize, String sigAlgName, int paramsType, String provider) throws Exception {
    //
    //        //System.out.println ("Sig algorithm=" + sigAlgName + " keyAlgName = " + keyAlgName);
    //        int validity = 365;
    //        if (keysize == -1) {
    //            if ("EC".equalsIgnoreCase(keyAlgName)) {
    //                keysize = 256;
    //            } else {
    //                keysize = 2048;
    //            }
    //        }
    //
    //        if (sigAlgName == null) {
    //            if (keyAlgName.equalsIgnoreCase("DSA")) {
    //                sigAlgName = "SHA256WithDSA";
    //            } else if (keyAlgName.equalsIgnoreCase("RSA")) {
    //                sigAlgName = "SHA256WithRSA";
    //            } else if (keyAlgName.equalsIgnoreCase("EC")) {
    //                sigAlgName = "SHA256withECDSA";
    //            } else {
    //                throw new Exception("Cannot derive signature algorithm");
    //            }
    //        } else {
    //            if (keyAlgName.equalsIgnoreCase("DSA")) {
    //                String sigAlgNameLower = sigAlgName.toLowerCase();
    //                if (sigAlgNameLower.indexOf("rsa") != -1) {
    //                    throw new Exception(
    //                            "Key algorithm and signature algorithm mismatch");
    //                }
    //            } else if (keyAlgName.equalsIgnoreCase("RSA")) {
    //                String sigAlgNameLower = sigAlgName.toLowerCase();
    //                if (sigAlgNameLower.indexOf("dsa") != -1) {
    //                    throw new Exception(
    //                            "Key algorithm and signature algorithm mismatch");
    //                }
    //            }
    //        }
    //        CertAndKeyGen keypair = new CertAndKeyGen(keyAlgName, sigAlgName,
    //                provider);
    //
    //        // If DN is provided, parse it. Otherwise, prompt the user for it.
    //        X500Name x500Name = new X500Name(dname);
    //
    //        Object[] source = { new Integer(keysize), keyAlgName, sigAlgName,
    //                x500Name };
    //        //System.err
    //        //        .println("Generating keysize bit keyAlgName key pair and self-signed certificate (sigAlgName)\n\tfor: x500Name"
    //        //                + source);
    //
    //        switch (paramsType) {
    //
    //        case EMPTY_PARAMS:
    //
    //            // Empty Parameters
    //
    //            keypair.generate(keysize);
    //            PrivateKey privKey = keypair.getPrivateKey();
    //            X509Certificate[] chain0 = new X509Certificate[1];
    //            chain0[0] = keypair.getSelfCert(x500Name,
    //                    (long) validity * 24 * 60 * 60);
    //
    //            byte[] derBytes0 = chain0[0].getEncoded();
    //            //System.out.println("signed certificate0=" + toHex(derBytes0));
    //
    //            InputStream is0 = new ByteArrayInputStream(derBytes0);
    //            X509Certificate certificate0 = (X509Certificate) CertificateFactory
    //                    .getInstance("X.509", "SunJCE").generateCertificate(is0);
    //            /* assertTrue(certificate0.getSigAlgParams() == null);*/
    //            // //System.out.println ("Certificate0 parameters=" +
    //            // toHex(certificate0.getSigAlgParams()));
    //            certificate0.checkValidity();
    //            certificate0.verify(certificate0.getPublicKey());
    //            break;
    //
    //        case DEFAULT_PARAMS:
    //            // All defaultParams
    //            PSSParameterSpec pssParameterSpec1 = PSSParameterSpec.DEFAULT;
    //            //System.out.println("pssParameterSpec1=" + pssParameterSpec1.getDigestAlgorithm() + " MGF " + pssParameterSpec1.getMGFAlgorithm() + " " + pssParameterSpec1.getSaltLength());
    //            //System.out.println("x500Name = " + x500Name);
    //            keypair.generate(keysize);
    //
    //            X509Certificate[] chain1 = new X509Certificate[1];
    //            chain1[0] = keypair.getSelfCert(x500Name,
    //                    (long) validity * 24 * 60 * 60, pssParameterSpec1);
    //
    //            byte[] derBytes1 = chain1[0].getEncoded();
    //            //System.out.println("signed certificate1=" + toHex(derBytes1));
    //
    //            InputStream is1 = new ByteArrayInputStream(derBytes1);
    //            X509Certificate certificate1 = (X509Certificate) CertificateFactory
    //                    .getInstance("X.509", "SunJCE").generateCertificate(is1);
    //            //System.out.println("Certificate1 parameters="
    //            //        + toHex(certificate1.getSigAlgParams()));
    //
    //            //X509CertImpl certImpl = (X509CertImpl) certificate1;
    //            
    //            certificate1.verify(certificate1.getPublicKey(), (String) null);
    //            
    ////            certImpl.verify(certificate1.getPublicKey(), null,
    ////                    certificate1.getSigAlgParams());
    //            certificate1.checkValidity();
    //            assertTrue(toHex(certificate1.getSigAlgParams()).equals("3000"));
    //            // Hex string was verified manually using asnDecoder utility
    //            //assertTrue(toHex(certificate1.getSigAlgParams())
    //            //        .equals("3027a00b300906052b0e03021a0500a118301606092a864886f70d010108300906052b0e03021a0500"));
    //            break;
    //
    //        case NONDEFAULT_PARAMS:
    //            // Non Default parameters
    //            PSSParameterSpec pssParameterSpec2 = specSHA256Salt20;
    //
    //            keypair.generate(keysize);
    //            X509Certificate[] chain2 = new X509Certificate[1];
    //
    //            chain2[0] = keypair.getSelfCert(x500Name,
    //                    (long) validity * 24 * 60 * 60,
    //                    (AlgorithmParameterSpec) pssParameterSpec2);
    //
    //            byte[] derBytes2 = chain2[0].getEncoded();
    //            //System.out.println("signed certificate2=" + toHex(derBytes2));
    //
    //            InputStream is2 = new ByteArrayInputStream(derBytes2);
    //            X509Certificate certificate2 = (X509Certificate) CertificateFactory
    //                    .getInstance("X.509", "SunJCE").generateCertificate(is2);
    //            //System.out.println("Certificate2 parameters="
    //            //        + toHex(certificate2.getSigAlgParams()));
    //            certificate2.verify(certificate2.getPublicKey(), (String)null);
    //            //X509CertImpl certImpl2 = (X509CertImpl) certificate2;
    //
    //            //certImpl2.verify(certificate2.getPublicKey(), null,
    //            //        certificate2.getSigAlgParams());
    //
    //            certificate2.checkValidity();
    //            String algString = toHex(certificate2.getSigAlgParams());
    //            assertTrue(algString.equals(hexSHA256Salt20));
    //            break;
    //
    //        case PARAMS_SALT40:
    //            PSSParameterSpec pssParameterSpec3 = new PSSParameterSpec(40);
    //            keypair.generate(keysize);
    //            X509Certificate[] chain3 = new X509Certificate[1];
    //
    //            chain3[0] = keypair.getSelfCert(x500Name,
    //                    (long) validity * 24 * 60 * 60,
    //                    (AlgorithmParameterSpec) pssParameterSpec3);
    //
    //            byte[] derBytes3 = chain3[0].getEncoded();
    //            //System.out.println("signed certificate3=" + toHex(derBytes3));
    //
    //            InputStream is3 = new ByteArrayInputStream(derBytes3);
    //            X509Certificate certificate3 = (X509Certificate) CertificateFactory
    //                    .getInstance("X.509", "SunJCE").generateCertificate(is3);
    //            //System.out.println("Certificate3 parameters="
    //            //        + toHex(certificate3.getSigAlgParams()));
    //            certificate3.checkValidity();
    //            
    //            certificate3.verify(certificate3.getPublicKey(), (String) null);
    ////            X509CertImpl certImpl3 = (X509CertImpl) certificate3;
    ////            certImpl3.verify(certificate3.getPublicKey(), null,
    ////                    certificate3.getSigAlgParams());
    //            assertTrue(toHex(certificate3.getSigAlgParams())
    //                    .equals("3005a203020128"));
    //            break;
    //
    //        default:
    //            assertTrue(false);
    //        }
    //
    //    }
    //
    //    /**
    //     * Creates a new key pair and self-signed certificate for Bouncy Castle
    //     */
    //    private void doGenKeyPairBC(String alias, String dname, String keyAlgName,
    //            int keysize, String sigAlgName, int paramsType, String provider) throws Exception {
    //
    //        int validity = 365;
    //        if (keysize == -1) {
    //            if ("EC".equalsIgnoreCase(keyAlgName)) {
    //                keysize = 256;
    //            } else {
    //                keysize = 2048;
    //            }
    //        }
    //
    //        if (sigAlgName == null) {
    //            if (keyAlgName.equalsIgnoreCase("DSA")) {
    //                sigAlgName = "SHA256WithDSA";
    //            } else if (keyAlgName.equalsIgnoreCase("RSA")) {
    //                sigAlgName = "SHA256WithRSA";
    //            } else if (keyAlgName.equalsIgnoreCase("EC")) {
    //                sigAlgName = "SHA256withECDSA";
    //            } else {
    //                throw new Exception("Cannot derive signature algorithm");
    //            }
    //        } else {
    //            if (keyAlgName.equalsIgnoreCase("DSA")) {
    //                String sigAlgNameLower = sigAlgName.toLowerCase();
    //                if (sigAlgNameLower.indexOf("rsa") != -1) {
    //                    throw new Exception(
    //                            "Key algorithm and signature algorithm mismatch");
    //                }
    //            } else if (keyAlgName.equalsIgnoreCase("RSA")) {
    //                String sigAlgNameLower = sigAlgName.toLowerCase();
    //                if (sigAlgNameLower.indexOf("dsa") != -1) {
    //                    throw new Exception(
    //                            "Key algorithm and signature algorithm mismatch");
    //                }
    //            }
    //        }
    //        CertAndKeyGen keypair = new CertAndKeyGen(keyAlgName, sigAlgName, 
    //                interopProviderName);
    //
    //        KeyPairGenerator keyPairGeneratorBC = KeyPairGenerator.getInstance(
    //                "RSA", provider);
    //
    //        // If DN is provided, parse it. Otherwise, prompt the user for it.
    //        X500Name x500Name = new X500Name(dname);
    //
    //        Object[] source = { new Integer(keysize), keyAlgName, sigAlgName,
    //                x500Name };
    ////        System.err
    ////                .println("Generating keysize bit keyAlgName key pair and self-signed certificate (sigAlgName)\n\tfor: x500Name"
    ////                        + source);
    //
    //        switch (paramsType) {
    //
    //        case EMPTY_PARAMS:
    //
    //            // Empty Parameters
    //
    //            keypair.generate(keysize);
    //            PrivateKey privKey = keypair.getPrivateKey();
    //            X509Certificate[] chain0 = new X509Certificate[1];
    //            chain0[0] = keypair.getSelfCert(x500Name,
    //                    (long) validity * 24 * 60 * 60);
    //
    //            byte[] derBytes0 = chain0[0].getEncoded();
    //            //System.out.println("signed certificate0=" + toHex(derBytes0));
    //
    //            InputStream is0 = new ByteArrayInputStream(derBytes0);
    //            X509Certificate certificate0 = (X509Certificate) CertificateFactory
    //                    .getInstance("X.509", interopProviderName).generateCertificate(is0);
    //            assertTrue(certificate0.getSigAlgParams() == null);
    //            // //System.out.println ("Certificate0 parameters=" +
    //            // toHex(certificate0.getSigAlgParams()));
    //            certificate0.checkValidity();
    //            // X509Certificate certBC = getPemCert(derBytes3);
    //            // certBC.verify(certBC.getPublicKey(), "BC");
    //            // String certInPEMFormat = convertToPEMFormat(certificate0);
    //            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
    //                    .getInstance("X.509", interopProviderName);
    //            InputStream istream = new ByteArrayInputStream(derBytes0);
    //            java.security.cert.Certificate cert = cf
    //                    .generateCertificate(istream);
    //            assertTrue(cert != null);
    //            cert.verify(cert.getPublicKey());
    //            assertTrue(Arrays.equals(cert.getEncoded(),
    //                    certificate0.getEncoded()));
    //
    //            break;
    //
    //        case DEFAULT_PARAMS:
    //            // All defaultParams
    //            PSSParameterSpec pssParameterSpec1 = PSSParameterSpec.DEFAULT;
    //
    //            keypair.generate(keysize);
    //
    //            X509Certificate[] chain1 = new X509Certificate[1];
    //            chain1[0] = keypair.getSelfCert(x500Name,
    //                    (long) validity * 24 * 60 * 60, pssParameterSpec1);
    //
    //            byte[] derBytes1 = chain1[0].getEncoded();
    //            //System.out.println("signed certificate1=" + toHex(derBytes1));
    //
    //            InputStream is1 = new ByteArrayInputStream(derBytes1);
    //            X509Certificate certificate1 = (X509Certificate) CertificateFactory
    //                    .getInstance("X.509", interopProviderName).generateCertificate(is1);
    //            //System.out.println("Certificate1 parameters="
    //            //        + toHex(certificate1.getSigAlgParams()));
    //
    //            X509CertImpl certImpl = (X509CertImpl) certificate1;
    //            certificate1.verify(certificate1.getPublicKey(), (String) null);
    //
    ////            certImpl.verify(certificate1.getPublicKey(), (Provider) null,
    ////                    certificate1.getSigAlgParams());
    //            certificate1.checkValidity();
    //            // Hex string was verified manually using asnDecoder utility
    //            //assertTrue(toHex(certificate1.getSigAlgParams())
    //        //            .equals("3027a00b300906052b0e03021a0500a118301606092a864886f70d010108300906052b0e03021a0500"));
    //
    //            java.security.cert.CertificateFactory cf1 = java.security.cert.CertificateFactory
    //                    .getInstance("X.509", interopProviderName);
    //            InputStream istream1 = new ByteArrayInputStream(derBytes1);
    //            java.security.cert.Certificate cert1 = cf1
    //                    .generateCertificate(istream1);
    //            assertTrue(cert1 != null);
    //            cert1.verify(cert1.getPublicKey());
    //            assertTrue(Arrays.equals(cert1.getEncoded(),
    //                    certificate1.getEncoded()));
    //            break;
    //
    //        case NONDEFAULT_PARAMS:
    //            // Non Default parameters
    //            PSSParameterSpec pssParameterSpec2 = specSHA256Salt40;
    //
    //            keypair.generate(keysize);
    //            X509Certificate[] chain2 = new X509Certificate[1];
    //
    //            chain2[0] = keypair.getSelfCert(x500Name,
    //                    (long) validity * 24 * 60 * 60,
    //                    (AlgorithmParameterSpec) pssParameterSpec2);
    //
    //            byte[] derBytes2 = chain2[0].getEncoded();
    //            //System.out.println("signed certificate2=" + toHex(derBytes2));
    //
    //            InputStream is2 = new ByteArrayInputStream(derBytes2);
    //            X509Certificate certificate2 = (X509Certificate) CertificateFactory
    //                    .getInstance("X.509", interopProviderName).generateCertificate(is2);
    //            //System.out.println("Certificate2 parameters="
    //            //        + toHex(certificate2.getSigAlgParams()));
    //            certificate2.verify (certificate2.getPublicKey(), (String)null);
    ////            X509CertImpl certImpl2 = (X509CertImpl) certificate2;
    //
    ////            certImpl2.verify(certificate2.getPublicKey(), null,
    ////                    certificate2.getSigAlgParams());
    //
    //            certificate2.checkValidity();
    //            assertTrue(toHex(certificate2.getSigAlgParams()).equals(hexSHA256Salt40));
    //            java.security.cert.CertificateFactory cf2 = java.security.cert.CertificateFactory
    //                    .getInstance("X.509", interopProviderName);
    //            InputStream istream2 = new ByteArrayInputStream(derBytes2);
    //            java.security.cert.Certificate cert2 = cf2
    //                    .generateCertificate(istream2);
    //            assertTrue(cert2 != null);
    //            
    //            try
    //            {
    //              cert2.verify(cert2.getPublicKey());
    //              //assertTrue(false);
    //            }
    //            catch (Exception e)
    //            {
    //                
    //                assertTrue(e.getMessage().contains("certificate does not verify with supplied key"));
    //            }
    //
    //            
    //            break;
    //
    //        case PARAMS_SALT40:
    //            PSSParameterSpec pssParameterSpec3 = new PSSParameterSpec(40);
    //            keypair.generate(keysize);
    //            X509Certificate[] chain3 = new X509Certificate[1];
    //
    //            chain3[0] = keypair.getSelfCert(x500Name,
    //                    (long) validity * 24 * 60 * 60,
    //                    (AlgorithmParameterSpec) pssParameterSpec3);
    //
    //            byte[] derBytes3 = chain3[0].getEncoded();
    //            //System.out.println("signed certificate3=" + toHex(derBytes3));
    //
    //            InputStream is3 = new ByteArrayInputStream(derBytes3);
    //            X509Certificate certificate3 = (X509Certificate) CertificateFactory
    //                    .getInstance("X.509", interopProviderName).generateCertificate(is3);
    //            //System.out.println("Certificate3 parameters="
    //            //        + toHex(certificate3.getSigAlgParams()));
    //            certificate3.checkValidity();
    //            //X509CertImpl certImpl3 = (X509CertImpl) certificate3;
    //            certificate3.verify(certificate3.getPublicKey(), (String)null);
    //            //assertTrue(toHex(certificate3.getSigAlgParams())
    //            //        .equals("302ca00b300906052b0e03021a0500a118301606092a864886f70d010108300906052b0e03021a0500a203020128"));
    //
    //            java.security.cert.CertificateFactory cf3 = java.security.cert.CertificateFactory
    //                    .getInstance("X.509", interopProviderName);
    //            InputStream istream3 = new ByteArrayInputStream(derBytes3);
    //            java.security.cert.Certificate cert3 = cf3
    //                    .generateCertificate(istream3);
    //            assertTrue(cert3 != null);
    //            cert3.verify(cert3.getPublicKey());
    //            assertTrue(Arrays.equals(cert3.getEncoded(),
    //                    certificate3.getEncoded()));
    //
    //            break;
    //
    //        default:
    //            assertTrue(false);
    //        }
    //
    //    }
    //
    //
    //
    //    @org.junit.Test
    //    public void testReadDefaultParams3rdPartyCertificates() throws IOException,
    //            CertificateException, InvalidKeyException,
    //            NoSuchAlgorithmException, NoSuchProviderException,
    //            SignatureException, InvalidParameterSpecException,
    //            InvalidAlgorithmParameterException {
    //        CertificateFactory certfact = CertificateFactory.getInstance("X.509");
    //
    //        String defaultParamsClientFileName = "src/test/java/ibm/jceplus/certs3rdparty/defaultParams/pssClientCert.pem";
    //        String defaultParamsRootFileName = "src/test/java/ibm/jceplus/certs3rdparty/defaultParams/pssRootCert.pem";
    //
    //        BufferedInputStream bisDefaultParamsRoot = null;
    //        File fileDefaultParamsRoot = new File(defaultParamsRootFileName);
    //        try {
    //            bisDefaultParamsRoot = new BufferedInputStream(new FileInputStream(
    //                    fileDefaultParamsRoot));
    //        } catch (FileNotFoundException e) {
    //            throw new IOException("Could not locate keyfile at '"
    //                    + defaultParamsRootFileName + "'", e);
    //        }
    //        byte[] defaultParamsRootBytes = new byte[(int) fileDefaultParamsRoot
    //                .length()];
    //        bisDefaultParamsRoot.read(defaultParamsRootBytes);
    //        bisDefaultParamsRoot.close();
    //
    //        // //System.out.println("emptyPSS=" + toHex(privKeyBytes1));
    //        InputStream isDefaultParamsRoot = new ByteArrayInputStream(
    //                defaultParamsRootBytes);
    //        X509Certificate certDefaultParamsRoot = (X509Certificate) CertificateFactory
    //                .getInstance("X.509").generateCertificate(isDefaultParamsRoot);
    //        //To-DO certDefaultParamsRoot.checkValidity();
    //        certDefaultParamsRoot.verify(certDefaultParamsRoot.getPublicKey());
    //
    //
    //        BufferedInputStream bisDefaultParamsClient = null;
    //        File fileDefaultParamsClient = new File(defaultParamsClientFileName);
    //        try {
    //            bisDefaultParamsClient = new BufferedInputStream(
    //                    new FileInputStream(fileDefaultParamsClient));
    //        } catch (FileNotFoundException e) {
    //            throw new IOException("Could not locate keyfile at '"
    //                    + defaultParamsClientFileName + "'", e);
    //        }
    //        byte[] defaultParamsClientBytes = new byte[(int) fileDefaultParamsClient
    //                .length()];
    //        bisDefaultParamsClient.read(defaultParamsClientBytes);
    //        bisDefaultParamsClient.close();
    //
    //        InputStream isDefaultParamsClient = new ByteArrayInputStream(
    //                defaultParamsClientBytes);
    //        X509Certificate certDefaultParamsClient = (X509Certificate) CertificateFactory
    //                .getInstance("X.509", interopProviderName)
    //                .generateCertificate(isDefaultParamsClient);
    //        
    //        
    //        certDefaultParamsClient.verify(certDefaultParamsRoot.getPublicKey(), (String)null);
    //
    //
    //    }
    //
    //    @org.junit.Test
    //    public void testReadEmptyParam3rdPartyCertificates() throws IOException,
    //            CertificateException, InvalidKeyException,
    //            NoSuchAlgorithmException, NoSuchProviderException,
    //            SignatureException, InvalidParameterSpecException,
    //            InvalidAlgorithmParameterException {
    //        CertificateFactory certfact = CertificateFactory.getInstance("X.509");
    //
    //        String emptyParamsClientFileName = "src/test/java/ibm/jceplus/certs3rdparty/emptyParams/pssClientCert.pem";
    //        String emptyParamsRootFileName = "src/test/java/ibm/jceplus/certs3rdparty/emptyParams/pssRootCert.pem";
    //
    //        BufferedInputStream bisEmptyParamsRoot = null;
    //        File fileEmptyParamsRoot = new File(emptyParamsRootFileName);
    //        try {
    //            bisEmptyParamsRoot = new BufferedInputStream(new FileInputStream(
    //                    fileEmptyParamsRoot));
    //        } catch (FileNotFoundException e) {
    //            throw new IOException("Could not locate keyfile at '"
    //                    + emptyParamsRootFileName + "'", e);
    //        }
    //        byte[] emptyParamsRootBytes = new byte[(int) fileEmptyParamsRoot
    //                .length()];
    //        bisEmptyParamsRoot.read(emptyParamsRootBytes);
    //        bisEmptyParamsRoot.close();
    //
    //        // //System.out.println("emptyPSS=" + toHex(privKeyBytes1));
    //        InputStream isEmptyParamsRoot = new ByteArrayInputStream(
    //                emptyParamsRootBytes);
    //        X509Certificate certEmptyParamsRoot = (X509Certificate) CertificateFactory
    //                .getInstance("X.509").generateCertificate(isEmptyParamsRoot);
    //        //certEmptyParamsRoot.checkValidity();
    //        // //System.out.println("certificate issuer " +
    //        // certificate1.getIssuerDN());
    //        // //System.out.println("certificate serialNumber " +
    //        // certificate1.getSerialNumber());
    //        // //System.out.println("certificate  sigOID " +
    //        // certificate1.getSigAlgOID());
    //        // //System.out.println("certificate  sigAlgName " +
    //        // certificate1.getSigAlgName());
    //        // //System.out.println("certificate  sigAlgParams " +
    //        // toHex(certificate1.getSigAlgParams ()));
    //        // //System.out.println("certificate  subjectDN " +
    //        // certificate1.getSubjectDN());
    //        
    //        certEmptyParamsRoot.verify(certEmptyParamsRoot.getPublicKey());
    //
    ////        X509CertImpl certImplEmptyParamsRoot = (X509CertImpl) certEmptyParamsRoot;
    ////        if (certEmptyParamsRoot.getSigAlgParams() != null) {
    ////            certImplEmptyParamsRoot.verify(certEmptyParamsRoot.getPublicKey(),
    ////                    null, certEmptyParamsRoot.getSigAlgParams());
    ////        } else {
    ////            certImplEmptyParamsRoot.verify(certEmptyParamsRoot.getPublicKey());
    ////        }
    //
    //        BufferedInputStream bisEmptyParamsClient = null;
    //        File fileEmptyParamsClient = new File(emptyParamsClientFileName);
    //        try {
    //            bisEmptyParamsClient = new BufferedInputStream(new FileInputStream(
    //                    fileEmptyParamsClient));
    //        } catch (FileNotFoundException e) {
    //            throw new IOException("Could not locate keyfile at '"
    //                    + emptyParamsClientFileName + "'", e);
    //        }
    //        byte[] emptyParamsClientBytes = new byte[(int) fileEmptyParamsClient
    //                .length()];
    //        bisEmptyParamsClient.read(emptyParamsClientBytes);
    //        bisEmptyParamsClient.close();
    //
    //        InputStream isEmptyParamsClient = new ByteArrayInputStream(
    //                emptyParamsClientBytes);
    //        X509Certificate certEmptyParamsClient = (X509Certificate) CertificateFactory
    //                .getInstance("X.509").generateCertificate(isEmptyParamsClient);
    //        //certEmptyParamsClient.checkValidity();
    //        
    //        certEmptyParamsClient.verify(certEmptyParamsRoot.getPublicKey(), (String)null);
    //
    ////        X509CertImpl certImplEmptyParamsClient = (X509CertImpl) certEmptyParamsClient;
    ////        if (certEmptyParamsClient.getSigAlgParams() != null) {
    ////            certImplEmptyParamsClient.verify(
    ////                    certEmptyParamsRoot.getPublicKey(), null,
    ////                    certEmptyParamsClient.getSigAlgParams());
    ////        } else {
    ////            certImplEmptyParamsRoot.verify(certEmptyParamsRoot.getPublicKey());
    ////        }
    //
    //    }
    //
    //    /**
    //     * Test parameter spec
    //     * @throws IOException
    //     */
    //    @org.junit.Test
    //    public void testParameterSpec() throws IOException {
    //        Signature sig_ibm = null;
    //        try {
    //            sig_ibm = Signature.getInstance(JCEPlus_ALG, providerName);
    //        } catch (NoSuchAlgorithmException e) {
    //            // TODO Auto-generated catch block
    //            e.printStackTrace();
    //            assertTrue(false);
    //        } catch (NoSuchProviderException e) {
    //            // TODO Auto-generated catch block
    //            e.printStackTrace();
    //            assertTrue(false);
    //        }
    //
    //        AlgorithmParameters algParams_ibm = sig_ibm.getParameters();
    ////        //System.out.println("algParams_ibm=" + algParams_ibm.toString());
    ////        hashAlgorithm: SHA
    ////        maskGenAlgorithm: MGF1
    ////        mgf1ParameterSpec: SHA-1
    ////        saltLength: 20
    ////        trailerField: 1
    //
    //        assertTrue (algParams_ibm.toString().contains("hashAlgorithm: SHA"));
    //        assertTrue (algParams_ibm.toString().contains("maskGenAlgorithm: MGF1"));
    //        assertTrue (algParams_ibm.toString().contains("mgf1ParameterSpec: SHA-1"));
    //        assertTrue (algParams_ibm.toString().contains("saltLength: 20"));
    //        assertTrue (algParams_ibm.toString().contains("trailerField: 1"));
    //        
    //
    //        PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA2",
    //                "MGF1", MGF1ParameterSpec.SHA1, 400, 1);
    //        try {
    //            sig_ibm.setParameter(pssParameterSpec);
    //        } catch (InvalidAlgorithmParameterException e1) {
    //            // TODO Auto-generated catch block
    //            e1.printStackTrace();
    //            assertTrue(false);
    //        }
    //
    //        AlgorithmParameters algParams_ibm1 = sig_ibm.getParameters();
    //        //System.out.println("algParams_ibm1=" + algParams_ibm1);
    //        assertTrue (algParams_ibm1.toString().contains("hashAlgorithm: SHA-256") || algParams_ibm1.toString().contains("hashAlgorithm: SHA2"));
    //        assertTrue (algParams_ibm1.toString().contains("saltLength: 400"));
    //
    //        Signature sig_bc = null;
    //        try {
    //            sig_bc = Signature.getInstance(SunJCE_ALG, "BC");
    //        } catch (NoSuchAlgorithmException e) {
    //            // TODO Auto-generated catch block
    //            e.printStackTrace();
    //            assertTrue(false);
    //        } catch (NoSuchProviderException e) {
    //            // TODO Auto-generated catch block
    //            e.printStackTrace();
    //            assertTrue(false);
    //        }
    //
    //        AlgorithmParameters algParams_bc = sig_bc.getParameters();
    //        ////System.out.println("algParams_bc=" + algParams_bc.toString());
    //
    //        ASN1InputStream aIn = new ASN1InputStream(
    //                algParams_bc.getEncoded("ASN.1"));
    //        ASN1Dump.dumpAsString(aIn.readObject()).equals("DER Sequence");
    //        
    //        PSSParameterSpec pssParameterSpec_bc = new PSSParameterSpec("SHA1",
    //                "MGF1", MGF1ParameterSpec.SHA1, 400, 1);
    //
    //        // PSSParameterSpec pssParameterSpec = new PSSParameterSpec(100);
    //        try {
    //            sig_bc.setParameter(pssParameterSpec_bc);
    //        } catch (InvalidAlgorithmParameterException e1) {
    //            // TODO Auto-generated catch block
    //            e1.printStackTrace();
    //            assertTrue(false);
    //        }
    //        AlgorithmParameters algParams_bc1 = sig_bc.getParameters();
    //        ASN1InputStream aIn_bc1 = new ASN1InputStream(
    //                algParams_bc1.getEncoded("ASN.1"));
    //        ASN1Dump.dumpAsString(aIn_bc1.readObject()).equals("Sequence\n\t\tTagged [2]\n\t\tInteger(400)");
    //        //Sequence
    //        //Tagged [2]
    //        //    Integer(400)
    //
    //        ////System.out.println("algParams_bc1=" + algParams_bc1.toString());
    //
    //    }



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
