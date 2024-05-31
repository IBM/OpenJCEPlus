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

public class TestXDHInterop extends ibm.jceplus.junit.base.BaseTestXDHInterop {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestXDHInterop() {
        super(Utils.TEST_SUITE_PROVIDER_NAME, Utils.PROVIDER_SunEC);
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
        TestSuite suite = new TestSuite(TestXDHInterop.class);
        return suite;
    }
}
