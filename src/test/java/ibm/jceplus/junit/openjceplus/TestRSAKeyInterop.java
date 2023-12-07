/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus;

import junit.framework.Test;
import junit.framework.TestSuite;

public class TestRSAKeyInterop extends ibm.jceplus.junit.base.BaseTestRSAKeyInterop {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSAKeyInterop() {
        //super(Utils.TEST_SUITE_PROVIDER_NAME, Utils.PROVIDER_IBMJCE); // Invalid
        super(Utils.TEST_SUITE_PROVIDER_NAME, Utils.PROVIDER_SunRsaSign); // Passed
        //super(Utils.TEST_SUITE_PROVIDER_NAME, Utils.PROVIDER_OpenJCEPlus); // Passed
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSAKeyInterop(int keySize) throws Exception {
        //super(Utils.TEST_SUITE_PROVIDER_NAME, Utils.PROVIDER_IBMJCE, keySize);
        super(Utils.TEST_SUITE_PROVIDER_NAME, Utils.PROVIDER_SunRsaSign, keySize); // Passed
        //super(Utils.TEST_SUITE_PROVIDER_NAME, Utils.PROVIDER_OpenJCEPlus, keySize); // Passed
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
        TestSuite suite = new TestSuite(TestRSAKeyInterop.class);
        return suite;
    }

    // --------------------------------------------------------------------------
    // This method is to check whether an algorithm is valid for the cipher
    // but not supported by a given provider.
    //
}

