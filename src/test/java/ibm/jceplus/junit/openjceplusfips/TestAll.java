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

@SelectClasses({
    TestAES_256.class,
    TestAES.class,
    TestAES256Interop.class,
    TestAESCCM.class,
    TestAESCCM2.class,
    TestAESCCMInteropBC.class,
    TestAESCCMParameters.class,
    TestAESCipherInputStreamExceptions.class,
    TestAESCopySafe.class,
    TestAESGCM_128.class,
    TestAESGCM_192.class,
    TestAESGCM_256.class,
    TestAESGCM_ExtIV.class,
    TestAESGCM_IntIV.class,
    TestAESGCM.class,
    TestAESGCMBufferIV.class,
    TestAESGCMCICOWithGCM.class,
    TestAESGCMCICOWithGCMAndAAD.class,
    TestAESGCMLong.class,
    TestAESGCMNonExpanding.class,
    TestAESGCMSameBuffer.class,
    TestAESGCMUpdate.class,
    TestAESGCMWithByteBuffer.class,
    TestAliases.class,
    TestDH.class,
    TestDHInteropSunJCE.class,
    TestDHKeyFactory.class,
    TestDHKeyPairGenerator.class,
    TestDHMultiParty.class,
    TestDSAKey.class,
    TestECDH.class,
    TestECDHInteropSunEC.class,
    TestECDHKeyAgreementParamValidation.class,
    TestECDHMultiParty.class,
    TestECDSASignature.class,
    TestECDSASignatureInteropSunEC.class,
    TestECKeyImport.class,
    TestECKeyImportInteropSunEC.class,
    TestECKeyPairGenerator.class,
    TestFIPSVerifyOnlyTest.class,
    TestHKDF.class,
    TestHKDFInterop.class,
    TestHmacSHA224.class,
    TestHmacSHA224InteropSunJCE.class,
    TestHmacSHA256.class,
    TestHmacSHA256InteropSunJCE.class,
    TestHmacSHA3_224.class,
    TestHmacSHA3_256.class,
    TestHmacSHA3_384.class,
    TestHmacSHA3_512.class,
    TestHmacSHA384.class,
    TestHmacSHA384InteropSunJCE.class,
    TestHmacSHA512.class,
    TestHmacSHA512InteropSunJCE.class,
    TestImplementationClassesExist.class,
    TestImplementationClassesFinal.class,
    TestInvalidArrayIndex.class,
    TestMiniRSAPSS2.class,
    TestPublicMethodsToMakeNonPublic.class,
    TestResetByteBuffer.class,
    TestRSA_2048.class,
    TestRSA_4096.class,
    TestRSA.class,
    TestRSAKey.class,
    TestRSAKeyInterop.class,
    TestRSAKeyInteropBC.class,
    TestRSAPSS.class,
    TestRSAPSS2.class,
    TestRSAPSSInterop2.class,
    TestRSAPSSInterop3.class,
    TestRSASignature.class,
    TestRSASignatureChunkUpdate.class,
    TestRSASignatureInteropSunRsaSign.class,
    TestRSASignatureWithSpecificSize.class,
    TestRSATypeCheckDefault.class,
    TestSHA1.class,
    TestSHA224.class,
    TestSHA256.class,
    TestSHA3_224.class,
    TestSHA3_256.class,
    TestSHA3_384.class,
    TestSHA3_512.class,
    TestSHA384.class,
    TestSHA512.class
})

@Suite
public class TestAll {
}
