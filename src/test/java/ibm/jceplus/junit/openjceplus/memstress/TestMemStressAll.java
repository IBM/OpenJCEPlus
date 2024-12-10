/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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
    TestMemStressRSAPSS2.class,
    TestMemStressRSASignature.class,
    TestMemStressSHA256.class,
    TestMemStressXDH_X25519.class,
    TestMemStressXDH_X448.class
})

@Suite
public class TestMemStressAll {
}
