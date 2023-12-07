/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestECDHInterop;
import ibm.jceplus.junit.openjceplusfips.Utils;

public class TestECDHInteropSunEC extends BaseTestECDHInterop {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestECDHInteropSunEC() {
        super(Utils.TEST_SUITE_PROVIDER_NAME, Utils.PROVIDER_SunEC);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testECDHInteropSunEC() throws Exception {
        System.out.println("executing testECDHInteropSunEC");
        BaseTestECDHInterop bt = new BaseTestECDHInterop(providerName, Utils.PROVIDER_SunEC);
        bt.run();

    }

    public static void main(String[] args) {
        String[] nargs = {
                ibm.jceplus.junit.openjceplusfips.multithread.TestECDHInteropSunEC.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }
}

