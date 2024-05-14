/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.memstress;

import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

@SelectClasses({TestMemStressAES256.class, TestMemStressAESGCM.class,
                TestMemStressChaChaPoly1305.class, TestMemStressDH.class, TestMemStressDHKeyPair.class,
                TestMemStressDHKeyFactory.class, TestMemStressDSASignature.class,
                TestMemStressDSAKeyPair.class, TestMemStressDSAKeyFactory.class,
                TestMemStressECKeyPair.class, TestMemStressECKeyFactory.class,
                TestMemStressECDSASignature.class, TestMemStressHKDF.class, TestMemStressHmacSHA256.class,
                TestMemStressRSAPSS2.class, TestMemStressRSASignature.class, TestMemStressSHA256.class,
                TestMemStressXDH_X25519.class, TestMemStressXDH_X448.class})

@Suite
public class TestMemStressAll {
}
