/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.memstress;

import junit.framework.JUnit4TestAdapter;
import junit.framework.Test;
import junit.framework.TestSuite;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({TestMemStressAES256.class, TestMemStressAESGCM.class,
        TestMemStressChaChaPoly1305.class, TestMemStressDH.class, TestMemStressDHKeyPair.class,
        TestMemStressDHKeyFactory.class, TestMemStressDSASignature.class,
        TestMemStressDSAKeyPair.class, TestMemStressDSAKeyFactory.class,
        TestMemStressECKeyPair.class, TestMemStressECKeyFactory.class,
        TestMemStressECDSASignature.class, TestMemStressHKDF.class, TestMemStressHmacSHA256.class,
        TestMemStressRSAPSS2.class, TestMemStressRSASignature.class, TestMemStressSHA256.class,
        TestMemStressXDH_X25519.class, TestMemStressXDH_X448.class})

public class TestMemStressAll {

    public static Test dynamic_suite() {
        TestSuite suite = new TestSuite();
        return suite;
    }

    public static Test suite() {
        return new JUnit4TestAdapter(TestMemStressAll.class);
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(suite());
    }

    //    private static boolean isCipherKeySizeSupported(String algorithm, int keySize) {
    //        try {
    //            return javax.crypto.Cipher.getMaxAllowedKeyLength(algorithm) >= keySize;
    //        } catch (Exception e) {
    //        }
    //        return false;
    //    }

}
