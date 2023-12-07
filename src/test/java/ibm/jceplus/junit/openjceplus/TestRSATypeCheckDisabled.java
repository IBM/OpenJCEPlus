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

/**
 *
 * This test should not be included in the TestAll test suite and should be
 * run as a standalone testcase.  This testcase sets a System property to
 * modify the behavior of the OpenJCEPlus provider.  This
 * property value is read by the provider once during static initialization.
 */
public class TestRSATypeCheckDisabled extends ibm.jceplus.junit.base.BaseTestRSATypeCheckDisabled {
    //--------------------------------------------------------------------------
    //
    //
    static {
        try {
            System.setProperty("com.ibm.crypto.provider.DoRSATypeChecking", "false");
        } catch (Throwable t) {
            t.printStackTrace(System.out);
        }

        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSATypeCheckDisabled() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
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
        TestSuite suite = new TestSuite(TestRSATypeCheckDisabled.class);
        return suite;
    }
}

