/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTest;
import ibm.jceplus.junit.openjceplusfips.Utils;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import junit.framework.Test;
import junit.framework.TestSuite;

public class TestAliases extends BaseTest {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestAliases() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAlgParams_3DES() throws Exception {
        try {
            AlgorithmParameters.getInstance("3DES", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: 3DES for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAlgParams_AESGCM() throws Exception {
        AlgorithmParameters.getInstance("AESGCM", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testAlgParamGen_AESGCM() throws Exception {
        AlgorithmParameterGenerator.getInstance("AESGCM", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testCipher_3DES() throws Exception {
        try {
            Cipher.getInstance("3DES", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("No such algorithm: 3DES", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testKeyFactory_DSAKeyFactory() throws Exception {
        KeyFactory.getInstance("DSAKeyFactory", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testKeyGen_3DES() throws Exception {
        try {
            KeyGenerator.getInstance("3DES", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: 3DES for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testKeyGen_HMACwithSHA1() throws Exception {
        try {
            KeyGenerator.getInstance("HMACwithSHA1", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: HMACwithSHA1 for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testKeyGen_HMACwithSHA224() throws Exception {
        KeyGenerator.getInstance("HMACwithSHA224", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testKeyGen_HMACwithSHA256() throws Exception {
        KeyGenerator.getInstance("HMACwithSHA256", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testKeyGen_HMACwithSHA384() throws Exception {
        KeyGenerator.getInstance("HMACwithSHA384", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testKeyGen_HMACwithSHA512() throws Exception {
        KeyGenerator.getInstance("HMACwithSHA512", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testKeyPairGen_OID_1_3_14_3_2_12() throws Exception {
        try {
            KeyPairGenerator.getInstance("OID.1.3.14.3.2.12", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: OID.1.3.14.3.2.12 for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    //public void testKeyStore_PKCS12KS() throws Exception {
    //    KeyStore.getInstance("PKCS12KS", providerName);
    //}

    //--------------------------------------------------------------------------
    //
    //
    public void testMac_HMACwithSHA1() throws Exception {
        try {
            Mac.getInstance("HMACwithSHA1", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: HMACwithSHA1 for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testMac_HMACwithSHA224() throws Exception {
        Mac.getInstance("HMACwithSHA224", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testMac_HMACwithSHA256() throws Exception {
        Mac.getInstance("HMACwithSHA256", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testMac_HMACwithSHA384() throws Exception {
        Mac.getInstance("HMACwithSHA384", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testMac_HMACwithSHA512() throws Exception {
        Mac.getInstance("HMACwithSHA512", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testMessageDigest_SHA224() throws Exception {
        MessageDigest.getInstance("SHA224", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testMessageDigest_SHA2() throws Exception {
        MessageDigest.getInstance("SHA2", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testMessageDigest_SHA_2() throws Exception {
        MessageDigest.getInstance("SHA-2", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testMessageDigest_SHA256() throws Exception {
        MessageDigest.getInstance("SHA256", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testMessageDigest_SHA3() throws Exception {
        MessageDigest.getInstance("SHA3", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testMessageDigest_SHA_3() throws Exception {
        MessageDigest.getInstance("SHA-3", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testMessageDigest_SHA384() throws Exception {
        MessageDigest.getInstance("SHA384", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testMessageDigest_SHA5() throws Exception {
        MessageDigest.getInstance("SHA5", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testMessageDigest_SHA_5() throws Exception {
        MessageDigest.getInstance("SHA-5", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testMessageDigest_SHA512() throws Exception {
        MessageDigest.getInstance("SHA512", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSecretKeyFactory_3DES() throws Exception {
        try {
            SecretKeyFactory.getInstance("3DES", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: 3DES for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSecureRandom_SHA2DRBG() throws Exception {
        SecureRandom.getInstance("SHA2DRBG", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSecureRandom_SHA5DRBG() throws Exception {
        SecureRandom.getInstance("SHA5DRBG", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA_1withDSA() throws Exception {
        try {
            Signature.getInstance("SHA-1withDSA", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: SHA-1withDSA for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA_1_DSA() throws Exception {
        try {
            Signature.getInstance("SHA-1/DSA", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: SHA-1/DSA for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA1_DSA() throws Exception {
        try {
            Signature.getInstance("SHA1/DSA", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: SHA1/DSA for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA_DSA() throws Exception {
        try {
            Signature.getInstance("SHA/DSA", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: SHA/DSA for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_DSS() throws Exception {
        try {
            Signature.getInstance("DSS", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: DSS for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHAwithDSA() throws Exception {
        try {
            Signature.getInstance("SHAwithDSA", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: SHAwithDSA for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_DSAWithSHA1() throws Exception {
        try {
            Signature.getInstance("DSAWithSHA1", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: DSAWithSHA1 for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_OID_1_3_14_3_2_13() throws Exception {
        try {
            Signature.getInstance("OID.1.3.14.3.2.13", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: OID.1.3.14.3.2.13 for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_OID_1_3_14_3_2_27() throws Exception {
        try {
            Signature.getInstance("OID.1.3.14.3.2.27", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: OID.1.3.14.3.2.27 for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA_224withDSA() throws Exception {
        Signature.getInstance("SHA-224withDSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA_224_DSA() throws Exception {
        Signature.getInstance("SHA-224/DSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA224_DSA() throws Exception {
        Signature.getInstance("SHA224/DSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA2withDSA() throws Exception {
        Signature.getInstance("SHA2withDSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA_2withDSA() throws Exception {
        Signature.getInstance("SHA-2withDSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA_256withDSA() throws Exception {
        Signature.getInstance("SHA-256withDSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA_2_DSA() throws Exception {
        Signature.getInstance("SHA-2/DSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA2_DSA() throws Exception {
        Signature.getInstance("SHA2/DSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHAwithECDSA() throws Exception {
        try {
            Signature.getInstance("SHAwithECDSA", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: SHAwithECDSA for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA_1withECDSA() throws Exception {
        try {
            Signature.getInstance("SHA-1withECDSA", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: SHA-1withECDSA for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA_ECDSA() throws Exception {
        try {
            Signature.getInstance("SHA/ECDSA", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: SHA/ECDSA for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA_1_ECDSA() throws Exception {
        try {
            Signature.getInstance("SHA-1/ECDSA", providerName);
        } catch (NoSuchAlgorithmException nsae) {
            if (providerName.equals("OpenJCEPlusFIPS")) {
                assertEquals("no such algorithm: SHA-1/ECDSA for provider OpenJCEPlusFIPS", nsae.getMessage());
                return;
            } else {
                throw nsae;
            }
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA224_ECDSA() throws Exception {
        Signature.getInstance("SHA224/ECDSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA2withECDSA() throws Exception {
        Signature.getInstance("SHA2withECDSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA2_ECDSA() throws Exception {
        Signature.getInstance("SHA2/ECDSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA3withECDSA() throws Exception {
        Signature.getInstance("SHA3withECDSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA3_ECDSA() throws Exception {
        Signature.getInstance("SHA3/ECDSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA5withECDSA() throws Exception {
        Signature.getInstance("SHA5withECDSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA5_ECDSA() throws Exception {
        Signature.getInstance("SHA5/ECDSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA_1withRSA() throws Exception {
        Signature.getInstance("SHA-1withRSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHAwithRSA() throws Exception {
        Signature.getInstance("SHAwithRSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA_1_RSA() throws Exception {
        Signature.getInstance("SHA-1/RSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA1_RSA() throws Exception {
        Signature.getInstance("SHA1/RSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA_RSA() throws Exception {
        Signature.getInstance("SHA/RSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_RSA() throws Exception {
        Signature.getInstance("RSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA224_RSA() throws Exception {
        Signature.getInstance("SHA224/RSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA2withRSA() throws Exception {
        Signature.getInstance("SHA2withRSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA2_RSA() throws Exception {
        Signature.getInstance("SHA2/RSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA3withRSA() throws Exception {
        Signature.getInstance("SHA3withRSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA3_RSA() throws Exception {
        Signature.getInstance("SHA3/RSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA5withRSA() throws Exception {

        Signature.getInstance("SHA5withRSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSignature_SHA5_RSA() throws Exception {
        Signature.getInstance("SHA5/RSA", providerName);
    }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {
                ibm.jceplus.junit.openjceplusfips.multithread.TestAliases.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testAliases() throws Exception {
        System.out.println("executing testAliases SHA5/RSA");
        Signature.getInstance("SHA5/RSA", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public static Test suite() {
        TestSuite suite = new TestSuite(TestAliases.class);
        return suite;
    }
}

