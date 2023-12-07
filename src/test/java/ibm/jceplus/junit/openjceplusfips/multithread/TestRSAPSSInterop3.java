/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestRSAPSSInterop3;
import ibm.jceplus.junit.openjceplusfips.Utils;

public class TestRSAPSSInterop3 extends ibm.jceplus.junit.base.BaseTestRSAPSSInterop3 {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSAPSSInterop3() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {
                ibm.jceplus.junit.openjceplusfips.multithread.TestRSAPSSInterop3.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testRSAPSSInterop3() throws Exception {
        System.out.println("executing testRSAPSSInterop3");
        BaseTestRSAPSSInterop3 bt = new BaseTestRSAPSSInterop3(providerName);
        bt.run();
    }

}

