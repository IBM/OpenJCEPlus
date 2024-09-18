/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips;

import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

@SelectClasses({TestAES.class, TestAES_128.class, TestAES256Interop.class, TestAESCCM.class,
        TestAESCCM2.class, TestAESCCMParameters.class, TestAESCCMInteropBC.class, TestAESGCM.class,
        TestAESGCMUpdate.class, TestAESGCM_128.class, TestAESGCM_ExtIV.class,
        TestAESGCM_IntIV.class, TestAESGCMCipherInputStreamExceptions.class,
        TestAESGCMCopySafe.class, TestAESGCMNonExpanding.class, TestAESGCMCICOWithGCM.class,
        TestAESGCMSameBuffer.class, TestAESGCMWithByteBuffer.class,
        TestAESGCMCICOWithGCMAndAAD.class, TestAESGCMLong.class, TestAESGCMBufferIV.class,
        TestAliases.class, TestDHKeyPairGenerator.class, TestDH.class, TestDHMultiParty.class,
        TestDHInteropSunJCE.class, TestDHKeyFactory.class, TestECDH.class,
        TestECDHInteropSunEC.class, TestECDHMultiParty.class, TestECDSASignature.class,
        TestECDSASignatureInteropSunEC.class, TestECKeyImport.class,
        TestECKeyImportInteropSunEC.class, TestECKeyPairGenerator.class, TestHKDF.class,
        TestHKDFInterop.class, TestHmacSHA224.class, TestHmacSHA224InteropSunJCE.class,
        TestHmacSHA256.class, TestHmacSHA256InteropSunJCE.class, TestHmacSHA384.class,
        TestHmacSHA384InteropSunJCE.class, TestHmacSHA512.class, TestHmacSHA512InteropSunJCE.class,
        TestHmacSHA3_224.class, TestHmacSHA3_256.class, TestHmacSHA3_384.class,
        TestHmacSHA3_512.class, TestImplementationClassesExist.class,
        TestImplementationClassesFinal.class, TestInvalidArrayIndex.class,
        TestPublicMethodsToMakeNonPublic.class, TestRSA.class, TestRSA_2048.class, TestRSAKey.class,
        TestRSAPSS.class, TestMiniRSAPSS2.class, TestRSASignature.class,
        TestRSASignatureInteropSunRsaSign.class, TestRSASignatureChunkUpdate.class,
        TestRSATypeCheckDefault.class, TestSHA1.class, TestSHA224.class, TestSHA256.class,
        TestSHA384.class, TestSHA512.class, TestRSAPSSInterop2.class, TestRSAPSSInterop3.class,
        TestSHA3_224.class, TestSHA3_256.class, TestSHA3_384.class, TestSHA3_512.class,
        TestRSAKeyInterop.class, TestRSAKeyInteropBC.class, TestRSAPSS2.class,
        TestFIPSVerifyOnlyTest.class, TestRSASignatureWithSpecificSize.class})

@Suite
public class TestAll {
}
