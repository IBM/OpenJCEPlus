/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.memstress;

import ibm.jceplus.junit.base.memstress.BaseTestMemStressECDSASignature;
import ibm.jceplus.junit.openjceplus.Utils;
import junit.framework.Test;
import junit.framework.TestSuite;

public class TestMemStressECDSASignature extends BaseTestMemStressECDSASignature {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestMemStressECDSASignature() {

        super(Utils.TEST_SUITE_PROVIDER_NAME, "SHA256withECDSA", 256);
    }

    //--------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        junit.textui.TestRunner.run(suite());
    }

    //--------------------------------------------------------------------------
    //
    //
    public static Test suite() {
        TestSuite suite = new TestSuite(TestMemStressECDSASignature.class);
        return suite;
    }
}

