/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestRSAPSSInterop2;
import ibm.jceplus.junit.openjceplusfips.Utils;

public class TestRSAPSSInterop2 extends ibm.jceplus.junit.base.BaseTestRSAPSSInterop2 {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSAPSSInterop2() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {
                ibm.jceplus.junit.openjceplusfips.multithread.TestRSAPSSInterop2.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testRSAPSSInterop2() throws Exception {
        System.out.println("executing testRSAPSSInterop2");
        BaseTestRSAPSSInterop2 bt = new BaseTestRSAPSSInterop2(providerName);
        bt.run();
    }

}

