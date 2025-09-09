/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplus.memstress;

import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

@SelectClasses({
    TestMemStressAES256.class,
    TestMemStressAESGCM.class,
    TestMemStressChaChaPoly1305.class,
    TestMemStressDH.class,
    TestMemStressDHKeyFactory.class,
    TestMemStressDHKeyPair.class,
    TestMemStressDSAKeyFactory.class,
    TestMemStressDSAKeyPair.class,
    TestMemStressDSASignature.class,
    TestMemStressECDSASignature.class,
    TestMemStressECKeyFactory.class,
    TestMemStressECKeyPair.class,
    TestMemStressHKDF.class,
    TestMemStressHmacSHA256.class,
    TestMemStressMLKEM.class,
    TestMemStressRSAPSS2.class,
    TestMemStressRSASignature.class,
    TestMemStressSHA256.class,
    TestMemStressXDH_X25519.class,
    TestMemStressXDH_X448.class
})

@Suite
public class TestMemStressAll {
}
