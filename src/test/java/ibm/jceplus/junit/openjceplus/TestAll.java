/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus;

import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

@SelectClasses({TestAES.class, TestAES_128.class, TestAES256Interop.class, TestAESCCM.class,
        TestAESCCM2.class, TestAESCCMParameters.class, TestAESCCMInteropBC.class, TestAESGCM.class,
        TestAESGCMUpdate.class, TestAESGCMUpdateInteropBC.class, TestAESGCM_128.class,
        TestAESGCM_ExtIV.class, TestAESGCM_IntIV.class, TestAESCipherInputStreamExceptions.class,
        TestAESCopySafe.class, TestAESGCMNonExpanding.class, TestAESGCMSameBuffer.class,
        TestAESGCMWithByteBuffer.class, TestAESGCMCICOWithGCM.class,
        TestAESGCMCICOWithGCMAndAAD.class, TestAESGCMLong.class, TestAESGCMBufferIV.class,
        TestAliases.class, TestByteArrayOutputDelay.class, TestChaCha20.class,
        TestChaCha20KAT.class, TestChaCha20NoReuse.class, TestChaCha20Poly1305.class,
        TestChaCha20Poly1305ByteBuffer.class, TestChaCha20Poly1305ChunkUpdate.class,
        TestDESede.class, TestDHKeyPairGenerator.class, TestDH.class, TestDHMultiParty.class,
        TestDHInteropSunJCE.class, TestDHKeyFactory.class, TestDSAKey.class, TestDSASignature.class,
        TestDSASignatureInteropSUN.class, TestDSASignatureInteropBC.class, TestECDH.class,
        TestECDHInteropSunEC.class, TestECDHKeyAgreementParamValidation.class, TestECDHMultiParty.class, 
        TestECDSASignature.class, TestECDSASignatureInteropSunEC.class, TestECDSASignatureInteropBC.class,
        TestECKeyImport.class, TestECKeyImportInteropSunEC.class, TestECKeyPairGenerator.class,
        TestHKDF.class, TestHKDFInterop.class, TestHmacMD5.class, TestHmacMD5InteropSunJCE.class,
        TestHmacSHA1.class, TestHmacSHA1InteropSunJCE.class, TestHmacSHA224.class,
        TestHmacSHA224InteropSunJCE.class, TestHmacSHA256.class, TestHmacSHA256InteropSunJCE.class,
        TestHmacSHA384.class, TestHmacSHA384InteropSunJCE.class, TestHmacSHA512.class,
        TestHmacSHA512InteropSunJCE.class, TestHmacSHA3_224.class, TestHmacSHA3_256.class,
        TestHmacSHA3_384.class, TestHmacSHA3_512.class, TestImplementationClassesExist.class,
        TestImplementationClassesFinal.class, TestMD5.class,
        TestInvalidArrayIndex.class, TestPublicMethodsToMakeNonPublic.class, TestResetByteBuffer.class, TestRSA.class,
        TestRSA_512.class, TestRSA_1024.class, TestRSA_2048.class, TestRSAKey.class, TestRSAPSS.class,
        TestRSAPSSInterop.class, TestRSAPSS2.class, TestMiniRSAPSS2.class, TestRSAPSSInterop2.class,
        TestRSAPSSInterop3.class, TestRSASignature.class, TestRSASignatureInteropSunRsaSign.class,
        TestRSASignatureChunkUpdate.class, TestRSATypeCheckDefault.class, TestSHA1.class,
        TestSHA224.class, TestSHA256.class, TestSHA384.class, TestSHA512.class,
        TestSHA512_224.class, TestSHA512_256.class, TestSHA3_224.class, TestSHA3_256.class,
        TestSHA3_384.class, TestSHA3_512.class, TestRSAKeyInterop.class, TestRSAKeyInteropBC.class,
        TestEdDSASignature.class, TestEdDSASignatureInterop.class, TestXDH.class,
        TestXDHInterop.class, TestXDHInteropBC.class, TestXDHMultiParty.class, TestXDHKeyPairGenerator.class,
        TestXDHKeyImport.class, TestIsAssignableFromOrder.class})

@Suite
public class TestAll {
}
