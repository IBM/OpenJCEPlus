/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import junit.framework.JUnit4TestAdapter;
import junit.framework.Test;
import junit.framework.TestSuite;

@RunWith(Suite.class)
@Suite.SuiteClasses({TestAES.class, TestAES_128.class, TestAES256Interop.class, TestAESCCM.class,
        TestAESCCM2.class, TestAESCCMParameters.class, TestAESCCMInteropBC.class, TestAESGCM.class,
        TestAESGCMUpdate.class, TestAESGCMUpdateInteropBC.class, TestAESGCM_128.class,
        TestAESGCM_ExtIV.class, TestAESGCM_IntIV.class, TestAESGCMCipherInputStreamExceptions.class,
        TestAESGCMCopySafe.class, TestAESGCMNonExpanding.class, TestAESGCMSameBuffer.class,
        TestAESGCMWithByteBuffer.class, TestAESGCMCICOWithGCM.class,
        TestAESGCMCICOWithGCMAndAAD.class, TestAESGCMLong.class, TestAESGCMBufferIV.class,
        TestAliases.class, TestByteArrayOutputDelay.class, TestChaCha20.class,
        TestChaCha20KAT.class, TestChaCha20NoReuse.class, TestChaCha20Poly1305.class,
        TestChaCha20Poly1305ByteBuffer.class, TestChaCha20Poly1305ChunkUpdate.class,
        TestDESede.class, TestDHKeyPairGenerator.class, TestDH.class, TestDHMultiParty.class,
        TestDHInteropSunJCE.class, TestDHKeyFactory.class, TestDSAKey.class, TestDSASignature.class,
        TestDSASignatureInteropSUN.class, TestDSASignatureInteropBC.class, TestECDH.class,
        TestECDHInteropSunEC.class, TestECDHMultiParty.class, TestECDSASignature.class,
        TestECDSASignatureInteropSunEC.class, TestECDSASignatureInteropBC.class,
        TestECKeyImport.class, TestECKeyImportInteropSunEC.class, TestECKeyPairGenerator.class,
        TestHKDF.class, TestHKDFInterop.class, TestHmacMD5.class, TestHmacMD5InteropSunJCE.class,
        TestHmacSHA1.class, TestHmacSHA1InteropSunJCE.class, TestHmacSHA224.class,
        TestHmacSHA224InteropSunJCE.class, TestHmacSHA256.class, TestHmacSHA256InteropSunJCE.class,
        TestHmacSHA384.class, TestHmacSHA384InteropSunJCE.class, TestHmacSHA512.class,
        TestHmacSHA512InteropSunJCE.class, TestHmacSHA3_224.class, TestHmacSHA3_256.class,
        TestHmacSHA3_384.class, TestHmacSHA3_512.class, TestImplementationClassesExist.class,
        TestImplementationClassesFinal.class, TestMD5.class,
        TestInvalidArrayIndex.class, TestPublicMethodsToMakeNonPublic.class, TestRSA.class,
        TestRSA_512.class, TestRSA_1024.class, TestRSA_2048.class, TestRSAKey.class, TestRSAPSS.class,
        TestRSAPSSInterop.class, TestRSAPSS2.class, TestMiniRSAPSS2.class, TestRSAPSSInterop2.class,
        TestRSAPSSInterop3.class, TestRSASignature.class, TestRSASignatureInteropSunRsaSign.class,
        TestRSASignatureChunkUpdate.class, TestRSATypeCheckDefault.class, TestSHA1.class,
        TestSHA224.class, TestSHA256.class, TestSHA384.class, TestSHA512.class,
        TestSHA512_224.class, TestSHA512_256.class, TestSHA3_224.class, TestSHA3_256.class,
        TestSHA3_384.class, TestSHA3_512.class, TestRSAKeyInterop.class, TestRSAKeyInteropBC.class,
        TestXDH.class, TestXDHInterop.class, TestXDHMultiParty.class, TestXDHKeyPairGenerator.class,
        TestXDHKeyImport.class

})

public class TestAll {

    public static Test dynamic_suite() {
        TestSuite suite = new TestSuite();
        suite.addTest(new JUnit4TestAdapter(TestAES.class));
        suite.addTest(new JUnit4TestAdapter(TestAES_128.class));
        if (isCipherKeySizeSupported("AES", 192)) {
            suite.addTest(new JUnit4TestAdapter(TestAES_192.class));
        }
        if (isCipherKeySizeSupported("AES", 256)) {
            suite.addTest(new JUnit4TestAdapter(TestAES_256.class));
        }

        suite.addTest(new JUnit4TestAdapter(TestAESCCM.class));
        suite.addTest(new JUnit4TestAdapter(TestAESCCM2.class));
        suite.addTest(new JUnit4TestAdapter(TestAESCCMParameters.class));
        suite.addTest(new JUnit4TestAdapter(TestAESCCMInteropBC.class));
        suite.addTest(new JUnit4TestAdapter(TestAESGCM.class));
        suite.addTest(new JUnit4TestAdapter(TestAESGCM_ExtIV.class));
        suite.addTest(new JUnit4TestAdapter(TestAESGCM_IntIV.class));

        suite.addTest(new JUnit4TestAdapter(TestAliases.class));

        suite.addTest(new JUnit4TestAdapter(TestChaCha20.class));
        suite.addTest(new JUnit4TestAdapter(TestChaCha20KAT.class));
        suite.addTest(new JUnit4TestAdapter(TestChaCha20NoReuse.class));
        suite.addTest(new JUnit4TestAdapter(TestChaCha20Poly1305.class));

        suite.addTest(new JUnit4TestAdapter(TestDESede.class));

        // suite.addTest(new JUnit4TestAdapter(TestDHKeyPairGenerator.class));
        // suite.addTest(new JUnit4TestAdapter(TestDHMultiParty.class));

        suite.addTest(new JUnit4TestAdapter(TestDSAKey.class));
        suite.addTest(new JUnit4TestAdapter(TestDSASignature.class));


        suite.addTest(new JUnit4TestAdapter(TestHmacMD5.class));
        suite.addTest(new JUnit4TestAdapter(TestHmacMD5InteropSunJCE.class));
        suite.addTest(new JUnit4TestAdapter(TestHmacSHA1.class));
        suite.addTest(new JUnit4TestAdapter(TestHmacSHA1InteropSunJCE.class));
        suite.addTest(new JUnit4TestAdapter(TestHmacSHA224.class));
        suite.addTest(new JUnit4TestAdapter(TestHmacSHA224InteropSunJCE.class));
        suite.addTest(new JUnit4TestAdapter(TestHmacSHA256.class));
        suite.addTest(new JUnit4TestAdapter(TestHmacSHA256InteropSunJCE.class));
        suite.addTest(new JUnit4TestAdapter(TestHmacSHA384.class));
        suite.addTest(new JUnit4TestAdapter(TestHmacSHA384InteropSunJCE.class));
        suite.addTest(new JUnit4TestAdapter(TestHmacSHA512.class));
        suite.addTest(new JUnit4TestAdapter(TestHmacSHA512InteropSunJCE.class));

        suite.addTest(new JUnit4TestAdapter(TestImplementationClassesExist.class));

        suite.addTest(new JUnit4TestAdapter(TestMD5.class));

        suite.addTest(new JUnit4TestAdapter(TestRSA.class));
        suite.addTest(new JUnit4TestAdapter(TestRSAKey.class));
        suite.addTest(new JUnit4TestAdapter(TestRSASignature.class));
        suite.addTest(new JUnit4TestAdapter(TestRSASignatureInteropSunRsaSign.class));
        suite.addTest(new JUnit4TestAdapter(TestRSATypeCheckDefault.class));
        // suite.addTest(new JUnit4TestAdapter(TestRSAPSSSignature.class));

        // // DO NOT ADD TO TEST SUITE, run separately
        // suite.addTest(new JUnit4TestAdapter(TestRSATypeCheckDisabled.class));

        // // DO NOT ADD TO TEST SUITE, run separately
        // suite.addTest(new JUnit4TestAdapter(TestRSATypeCheckEnabled.class));

        suite.addTest(new JUnit4TestAdapter(TestSHA1.class));
        suite.addTest(new JUnit4TestAdapter(TestSHA224.class));
        suite.addTest(new JUnit4TestAdapter(TestSHA256.class));
        suite.addTest(new JUnit4TestAdapter(TestSHA384.class));
        suite.addTest(new JUnit4TestAdapter(TestSHA512.class));
        suite.addTest(new JUnit4TestAdapter(TestSHA512_224.class));
        suite.addTest(new JUnit4TestAdapter(TestSHA512_256.class));
        return suite;
    }

    public static Test suite() {
        return new JUnit4TestAdapter(TestAll.class);
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(suite());
    }

    private static boolean isCipherKeySizeSupported(String algorithm, int keySize) {
        try {
            return javax.crypto.Cipher.getMaxAllowedKeyLength(algorithm) >= keySize;
        } catch (Exception e) {
        }
        return false;
    }

}
