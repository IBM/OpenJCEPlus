/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips;

import junit.framework.Test;
import junit.framework.TestSuite;

public class TestRSAKeyInterop extends ibm.jceplus.junit.base.BaseTestRSAKeyInterop {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
        try {
            Utils.loadProviderOpenJCEPlusFIPS();
        } catch (Exception e) {
            e.printStackTrace(System.out);
            System.exit(1);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSAKeyInterop() throws Exception {
        super(Utils.TEST_SUITE_PROVIDER_NAME, Utils.PROVIDER_SunRsaSign, 2048);
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

}

